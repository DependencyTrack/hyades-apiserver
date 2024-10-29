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
import org.dependencytrack.job.JobEvent;
import org.dependencytrack.job.JobEvent.JobCompletedEvent;
import org.dependencytrack.job.JobEvent.JobFailedEvent;
import org.dependencytrack.job.JobEvent.JobStartedEvent;
import org.dependencytrack.job.JobEventListener;
import org.dependencytrack.job.JobManager;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.dependencytrack.workflow.WorkflowDao.NewWorkflowRun;
import org.dependencytrack.workflow.WorkflowDao.WorkflowRunTransition;
import org.dependencytrack.workflow.WorkflowDao.WorkflowStepRunTransition;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
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
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

// TODO: Metrics instrumentation
public class WorkflowEngine implements JobEventListener, Closeable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngine.class);
    private static final WorkflowEngine INSTANCE = new WorkflowEngine();

    private final BlockingQueue<JobEvent> jobEventQueue = new ArrayBlockingQueue<>(100);
    private final ScheduledExecutorService jobEventFlushExecutor;
    private final long jobEventFlushIntervalSeconds = 5;
    private final ReentrantLock jobEventFlushLock = new ReentrantLock();
    private final AtomicBoolean isShuttingDown = new AtomicBoolean(false);

    public WorkflowEngine() {
        // TODO: Move this to a start() method and make sure the engine can be restarted if stopped.
        // TODO: Find reasonable defaults for queue size and flush interval.
        jobEventFlushExecutor = Executors.newSingleThreadScheduledExecutor();
        jobEventFlushExecutor.scheduleAtFixedRate(this::flushJobEvents, 1, jobEventFlushIntervalSeconds, TimeUnit.SECONDS);
    }

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    // TODO: Listeners for workflow run state change?
    // TODO: Listeners for workflow step run state change?
    // TODO: Share transaction with JobManager?

    public void deploy(final WorkflowSpec spec) {
        assertRunning();

        // TODO: Validate spec

        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            LOGGER.info("Deploying workflow %s/%d".formatted(spec.name(), spec.version()));
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

    public List<WorkflowRunView> startWorkflows(final Collection<StartWorkflowOptions> options) {
        assertRunning();
        requireNonNull(options);

        final var jobsToQueue = new ArrayList<NewJob>();
        final List<WorkflowRunView> startedWorkflowRuns = inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final Map<Long, WorkflowRun> workflowRunById = dao.createWorkflowRuns(options.stream()
                            .map(startOptions -> new NewWorkflowRun(
                                    startOptions.name(),
                                    startOptions.version(),
                                    UUID.randomUUID()))
                            .toList())
                    .stream()
                    .collect(Collectors.toMap(WorkflowRun::id, Function.identity()));
            if (workflowRunById.size() != options.size()) {
                throw new IllegalStateException("Expected to start %d workflow runs, but only started %d".formatted(
                        options.size(), workflowRunById.size()));
            }

            final Map<Long, List<WorkflowStepRun>> workflowStepRunsByWorkflowRunId = dao.createWorkflowStepRuns(workflowRunById.values()).stream()
                    .collect(Collectors.groupingBy(WorkflowStepRun::workflowRunId, Collectors.toList()));

            final var workflowRunViews = new ArrayList<WorkflowRunView>(workflowRunById.size());
            for (final Map.Entry<Long, List<WorkflowStepRun>> entry : workflowStepRunsByWorkflowRunId.entrySet()) {
                final WorkflowRun workflowRun = workflowRunById.get(entry.getKey());
                final List<WorkflowStepRun> workflowStepRuns = entry.getValue();

                workflowRunViews.add(new WorkflowRunView(
                        "", // TODO: Get this.
                        1, // TODO: Get this.
                        workflowRun.token(),
                        workflowRun.priority(),
                        workflowRun.status(),
                        workflowRun.createdAt(),
                        workflowRun.updatedAt(),
                        workflowRun.startedAt()));
            }

            final List<ClaimedWorkflowStepRun> claimedStepRuns = dao.claimRunnableStepRunsOfType(
                    workflowRunById.keySet(), WorkflowStepType.JOB);
            if (!claimedStepRuns.isEmpty()) {
                jobsToQueue.addAll(claimedStepRuns.stream()
                        .map(claimedStepRun -> new NewJob(
                                claimedStepRun.stepName(),
                                claimedStepRun.priority(),
                                /* scheduledFor */ null,
                                /* payloadType */ null,
                                /* payload */ null,
                                claimedStepRun.workflowRunId(),
                                claimedStepRun.id()))
                        .toList());
            }

            return workflowRunViews;
        });

        if (!jobsToQueue.isEmpty()) {
            final List<QueuedJob> queuedJobs = JobManager.getInstance().enqueueAll(jobsToQueue);
            LOGGER.info("Queued %d jobs".formatted(queuedJobs.size()));
        }

        return startedWorkflowRuns;
    }

    public WorkflowRunView startWorkflow(final StartWorkflowOptions options) {
        final List<WorkflowRunView> startedWorkflows = startWorkflows(List.of(options));
        if (startedWorkflows.size() != 1) {
            throw new IllegalStateException("Workflow was not started");
        }

        return startedWorkflows.getFirst();
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

    @Override
    public void onJobEvent(final JobEvent event) {
        final boolean isRelevant = event instanceof JobCompletedEvent
                                   || event instanceof JobFailedEvent
                                   || event instanceof JobStartedEvent;
        if (!isRelevant || event.job().workflowStepRunId() == null) {
            return;
        }

        final boolean queued;
        try {
            queued = jobEventQueue.offer(event, jobEventFlushIntervalSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Thread was interrupted while waiting to enqueue %s".formatted(event), e);
        }

        if (!queued) {
            flushJobEvents();
            if (!jobEventQueue.offer(event)) {
                // Shouldn't ever happen, but without an exception we might never know when it does.
                throw new IllegalStateException("%s could not be queued even after flushing queued events".formatted(event));
            }
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
            flushJobEventsLocked();
        } finally {
            jobEventFlushLock.unlock();
        }
    }

    private void flushJobEventsLocked() {
        assert jobEventFlushLock.isHeldByCurrentThread();

        if (jobEventQueue.isEmpty()) {
            LOGGER.debug("Nothing to flush");
            return;
        }

        LOGGER.debug("%d events in flush queue".formatted(jobEventQueue.size()));
        final var latestEventByStepRunId = new HashMap<Long, JobEvent>();
        while (jobEventQueue.peek() != null) {
            final JobEvent event = jobEventQueue.poll();
            latestEventByStepRunId.put(event.job().workflowStepRunId(), event);
        }

        final var transitions = new ArrayList<WorkflowStepRunTransition>(latestEventByStepRunId.size());
        for (final Map.Entry<Long, JobEvent> entry : latestEventByStepRunId.entrySet()) {
            final long stepRunId = entry.getKey();
            final JobEvent event = entry.getValue();

            switch (event) {
                case JobCompletedEvent ignored -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId, WorkflowStepRunStatus.COMPLETED));
                case JobFailedEvent ignored -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId, WorkflowStepRunStatus.FAILED));
                case JobStartedEvent ignored -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId, WorkflowStepRunStatus.RUNNING));
                default -> throw new IllegalStateException("Unexpected event: " + event);
            }
        }

        final var jobsToQueue = new ArrayList<NewJob>();
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final List<WorkflowStepRun> transitionedStepRuns = dao.transitionStepRuns(transitions);
            if (transitionedStepRuns.size() != transitions.size()) {
                throw new IllegalStateException("Should have transitioned %d step runs, but only did %d".formatted(
                        transitions.size(), transitionedStepRuns.size()));
            }

            LOGGER.info("Transitioned status of %d workflow step runs".formatted(transitionedStepRuns.size()));
            final Map<WorkflowStepRunStatus, List<WorkflowStepRun>> stepRunsByStatus = transitionedStepRuns.stream()
                    .collect(Collectors.groupingBy(WorkflowStepRun::status, Collectors.toList()));

            final List<WorkflowStepRun> completedStepRuns = stepRunsByStatus.get(WorkflowStepRunStatus.COMPLETED);
            if (completedStepRuns != null) {
                final List<ClaimedWorkflowStepRun> claimedStepRuns = dao.claimRunnableStepRunsOfType(
                        completedStepRuns.stream().map(WorkflowStepRun::workflowRunId).toList(), WorkflowStepType.JOB);
                jobsToQueue.addAll(claimedStepRuns.stream()
                        .map(claimedStepRun -> new NewJob(
                                claimedStepRun.stepName(),
                                claimedStepRun.priority(),
                                /* scheduledFor */ null,
                                /* payloadType */ null,
                                /* payload */ null,
                                claimedStepRun.workflowRunId(),
                                claimedStepRun.id()))
                        .toList());

                final List<WorkflowRun> completedWorkflowRuns = dao.completeWorkflowRunsWhenAllStepRunsCompleted(
                        completedStepRuns.stream().map(WorkflowStepRun::workflowRunId).toList());
                LOGGER.info("Completed %d workflow runs".formatted(completedWorkflowRuns.size()));
            }

            final List<WorkflowStepRun> failedStepRuns = stepRunsByStatus.get(WorkflowStepRunStatus.FAILED);
            if (failedStepRuns != null) {
                final List<WorkflowStepRun> cancelledStepRuns = dao.cancelDependantStepRuns(failedStepRuns);
                LOGGER.info("Cancelled %d workflow step runs".formatted(cancelledStepRuns.size()));

                final List<WorkflowRun> failedWorkflowRuns = dao.transitionWorkflowRuns(failedStepRuns.stream()
                        .map(stepRun -> new WorkflowRunTransition(
                                stepRun.workflowRunId(),
                                WorkflowRunStatus.FAILED))
                        .toList());
                LOGGER.info("Failed %d workflow runs".formatted(failedWorkflowRuns.size()));
            }
        });

        if (!jobsToQueue.isEmpty()) {
            final List<QueuedJob> queuedJobs = JobManager.getInstance().enqueueAll(jobsToQueue);
            LOGGER.info("Queued %s jobs".formatted(queuedJobs.size()));
        }
    }

    private void assertRunning() {
        if (isShuttingDown.get()) {
            throw new IllegalStateException("Workflow engine is shutting down");
        }
    }

}
