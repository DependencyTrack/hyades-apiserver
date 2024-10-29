/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.workflow;

import alpine.common.logging.Logger;
import org.dependencytrack.job.JobManager;
import org.dependencytrack.job.JobStatus;
import org.dependencytrack.job.JobStatusListener;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;

import java.io.Closeable;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

// TODO: Metrics instrumentation
public class WorkflowEngine implements JobStatusListener, Closeable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngine.class);
    private static final WorkflowEngine INSTANCE = new WorkflowEngine();

    private final BlockingQueue<QueuedJob> jobEventQueue = new ArrayBlockingQueue<>(100);
    private final ScheduledExecutorService jobEventFlushExecutor;
    private final ReentrantLock jobEventFlushLock = new ReentrantLock();
    private final AtomicBoolean isShuttingDown = new AtomicBoolean(false);

    public WorkflowEngine() {
        // TODO: Move this to a start() method and make sure the engine can be restarted if stopped.
        jobEventFlushExecutor = Executors.newSingleThreadScheduledExecutor();
        jobEventFlushExecutor.scheduleAtFixedRate(this::flushJobEvents, 1, 5, TimeUnit.SECONDS);
    }

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    // TODO: Listeners for workflow run state change?
    // TODO: Listeners for workflow step run state change?
    // TODO: Share transaction with JobManager?

    public void deploy(final WorkflowSpec spec) {
        assertRunning();

        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            LOGGER.info("Deploying workflow %s v%d".formatted(spec.name(), spec.version()));
            final Workflow workflow = dao.createWorkflow(new NewWorkflow(spec.name(), spec.version()));

            final var workflowStepByName = new HashMap<String, WorkflowStep>(spec.stepSpecs().size());
            final var workflowStepDependencies = new HashMap<String, Set<String>>();
            for (final WorkflowStepSpec stepSpec : spec.stepSpecs()) {
                final WorkflowStep step = dao.createStep(new NewWorkflowStep(workflow.id(), stepSpec.name(), stepSpec.type()));
                workflowStepByName.put(step.name(), step);

                if (!stepSpec.stepDependencies().isEmpty()) {
                    workflowStepDependencies.put(step.name(), stepSpec.stepDependencies());
                }
            }

            for (final Map.Entry<String, Set<String>> entry : workflowStepDependencies.entrySet()) {
                final String stepName = entry.getKey();
                final Set<String> dependencyNames = entry.getValue();

                final WorkflowStep step = workflowStepByName.get(stepName);
                for (final String dependencyName : dependencyNames) {
                    final WorkflowStep dependencyStep = workflowStepByName.get(dependencyName);
                    dao.createStepDependency(step.id(), dependencyStep.id());
                }
            }
        });
    }

    public WorkflowRunView startWorkflow(final StartWorkflowOptions options) {
        assertRunning();
        requireNonNull(options);

        final WorkflowRunView startedWorkflowRun = inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final Workflow workflow = dao.getWorkflowByNameAndVersion(options.name(), options.version());
            if (workflow == null) {
                throw new NoSuchElementException("Workflow %s/%d does not exist".formatted(options.name(), options.version()));
            }

            final List<WorkflowStep> steps = dao.getStepsByWorkflow(workflow);
            if (steps == null || steps.isEmpty()) {
                throw new IllegalStateException("Workflow %s/%d has no steps".formatted(workflow.name(), workflow.version()));
            }

            LOGGER.info("Starting workflow %s/%d".formatted(workflow.name(), workflow.version()));
            final WorkflowRun workflowRun = dao.createWorkflowRun(workflow, UUID.randomUUID());
            final List<WorkflowStepRunView> stepRunViews = steps.stream()
                    .map(step -> {
                        final WorkflowStepRun stepRun = dao.createStepRun(workflowRun, step);
                        return new WorkflowStepRunView(
                                step.name(),
                                step.type(),
                                stepRun.status(),
                                stepRun.createdAt(),
                                stepRun.updatedAt(),
                                stepRun.startedAt());
                    })
                    .toList();

            return new WorkflowRunView(
                    workflow.name(),
                    workflow.version(),
                    workflowRun.token(),
                    workflowRun.priority(),
                    workflowRun.status(),
                    workflowRun.createdAt(),
                    workflowRun.updatedAt(),
                    workflowRun.startedAt(),
                    stepRunViews);
        });

        queueRunnableSteps(startedWorkflowRun.token());

        return startedWorkflowRun;
    }

    public Optional<WorkflowRunView> getWorkflowRun(final UUID token) {
        return inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final WorkflowRunView workflowRun = dao.getWorkflowRunViewByToken(token);
            if (workflowRun == null) {
                return Optional.empty();
            }

            final List<WorkflowStepRunView> stepRuns = dao.getStepRunViewsByToken(token);

            return Optional.of(new WorkflowRunView(
                    workflowRun.workflowName(),
                    workflowRun.workflowVersion(),
                    workflowRun.token(),
                    workflowRun.priority(),
                    workflowRun.status(),
                    workflowRun.createdAt(),
                    workflowRun.updatedAt(),
                    workflowRun.startedAt(),
                    stepRuns));
        });
    }

    public Optional<ClaimedWorkflowStepRun> claimStepRun(final UUID token, String stepName) {
        return inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);
            final ClaimedWorkflowStepRun claimedStepRun = dao.claimRunnableStepRun(token, stepName);
            return Optional.ofNullable(claimedStepRun);
        });
    }

    public void completeStepRun(final ClaimedWorkflowStepRun stepRun) {
        // TODO: Make this batch friendly.
        useJdbiTransaction(handle -> {
            // TODO: Handle illegal transitions.
            final var dao = handle.attach(WorkflowDao.class);
            dao.transitionStepRun(stepRun.id(), WorkflowStepRunStatus.COMPLETED);
        });

        // TODO: Check if entire workflow run can be completed.
        queueRunnableSteps(stepRun.token());
    }

    public void failStepRun(final ClaimedWorkflowStepRun stepRun) {
        // TODO: Make this batch friendly.
        useJdbiTransaction(handle -> {
            // TODO: Handle illegal transitions.
            final var dao = handle.attach(WorkflowDao.class);
            dao.transitionStepRun(stepRun.id(), WorkflowStepRunStatus.FAILED);
            final int cancelledStepRuns = dao.cancelDependantStepRuns(stepRun.workflowRunId(), stepRun.stepId());
            LOGGER.info("Cancelled %d dependant step runs".formatted(cancelledStepRuns));
            dao.transitionWorkflowRun(stepRun.workflowRunId(), WorkflowRunStatus.FAILED);
            LOGGER.info("Failed workflow run %s".formatted(stepRun.token()));
        });
    }

    public void restartStepRun(final UUID token, String stepName) {
        assertRunning();

        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);
            final WorkflowStepRun stepRun = dao.getStepRunForUpdateByTokenAndName(token, stepName);
            if (stepRun == null) {
                throw new NoSuchElementException("No step run exists for token %s and name %s".formatted(token, stepName));
            }

            if (!stepRun.status().canTransition(WorkflowStepRunStatus.PENDING)) {
                throw new IllegalStateException("Can not transition step run from %s to %s".formatted(
                        stepRun.status(), WorkflowStepRunStatus.PENDING));
            }

            final boolean transitioned = dao.transitionStepRun(stepRun.id(), WorkflowStepRunStatus.PENDING);
            if (!transitioned) {
                throw new IllegalStateException("Did not transition step run from %s to %s".formatted(
                        stepRun.status(), WorkflowStepRunStatus.PENDING));
            }
        });
    }

    private void queueRunnableSteps(final UUID token) {
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);
            final List<ClaimedWorkflowStepRun> claimedStepRuns = dao.claimRunnableStepRuns(token, null);
            for (final ClaimedWorkflowStepRun claimedStepRun : claimedStepRuns) {
                LOGGER.info("Claimed workflow step run: %s".formatted(claimedStepRun));
                if (claimedStepRun.stepType() != WorkflowStepType.JOB) {
                    throw new IllegalStateException("Invalid step type: %s".formatted(claimedStepRun.stepType()));
                }

                final QueuedJob queuedJob = JobManager.getInstance().enqueue(new NewJob(
                        claimedStepRun.stepName(),
                        /* priority */ claimedStepRun.priority(),
                        /* scheduledFor */ Instant.now(),
                        /* payloadType */ null,
                        /* payload */ null,
                        /* workflowRunId */ claimedStepRun.workflowRunId(),
                        /* workflowStepRunId */ claimedStepRun.id()));
                LOGGER.info("Queued job: %s".formatted(queuedJob));
            }
        });
    }

    @Override
    public void onStatusChanged(final QueuedJob queuedJob) {
        if (queuedJob.workflowStepRunId() == null) {
            return;
        }

        final boolean queued;
        try {
            queued = jobEventQueue.offer(queuedJob, 3, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        if (!queued) {
            flushJobEvents();
            jobEventQueue.offer(queuedJob); // TODO: Assert success
        }
    }

    @Override
    public void close() throws IOException {
        isShuttingDown.set(true);

        jobEventFlushExecutor.shutdown();
        try {
            final boolean terminated = jobEventFlushExecutor.awaitTermination(30, TimeUnit.SECONDS);
            if (!terminated) {
                LOGGER.warn("Flush executor did not terminate");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        flushJobEvents();
    }

    private void flushJobEvents() {
        jobEventFlushLock.lock();
        try {
            if (jobEventQueue.isEmpty()) {
                LOGGER.info("Nothing to flush");
                return;
            }

            LOGGER.info("Flushing %d events".formatted(jobEventQueue.size()));
            final var latestEventByStepRunId = new HashMap<Long, QueuedJob>();
            while (jobEventQueue.peek() != null) {
                final QueuedJob event = jobEventQueue.poll();
                latestEventByStepRunId.put(event.workflowStepRunId(), event);
            }

            // TODO: Move to DAO
            final List<Map<String, Object>> foo = withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "WFR"."TOKEN" AS "token"
                             , "WFR"."ID" AS "run_id"
                             , "WFSR"."WORKFLOW_STEP_ID" AS "step_id"
                             , "WFSR"."ID" AS "step_run_id"
                          FROM "WORKFLOW_STEP_RUN" AS "WFSR"
                         INNER JOIN "WORKFLOW_RUN" AS "WFR"
                            ON "WFR"."ID" = "WFSR"."WORKFLOW_RUN_ID"
                         WHERE "WFSR"."ID" = ANY(:stepRunIds)
                        """)
                    .bindArray("stepRunIds", Long.class, latestEventByStepRunId.keySet())
                    .mapToMap()
                    .list());

            // TODO: Do this in a batch.
            for (final Map<String, Object> results : foo) {
                final QueuedJob event = latestEventByStepRunId.get((long) results.get("step_run_id"));
                if (event.status() == JobStatus.COMPLETE) {
                    completeStepRun(new ClaimedWorkflowStepRun(
                            event.workflowStepRunId(),
                            (long) results.get("step_id"),
                            (long) results.get("run_id"),
                            (UUID) results.get("token"),
                            null, null, null, null));
                } else if (event.status() == JobStatus.FAILED) {
                    failStepRun(new ClaimedWorkflowStepRun(
                            event.workflowStepRunId(),
                            (long) results.get("step_id"),
                            (long) results.get("run_id"),
                            (UUID) results.get("token"),
                            null, null, null, null));
                }
            }
        } finally {
            jobEventFlushLock.unlock();
        }
    }

    private void assertRunning() {
        if (isShuttingDown.get()) {
            throw new IllegalStateException("Workflow engine is shutting down");
        }
    }

}
