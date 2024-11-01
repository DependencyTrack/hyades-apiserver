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
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.dependencytrack.job.JobEngine;
import org.dependencytrack.job.JobEvent;
import org.dependencytrack.job.JobEvent.JobCompletedEvent;
import org.dependencytrack.job.JobEvent.JobFailedEvent;
import org.dependencytrack.job.JobEvent.JobStartedEvent;
import org.dependencytrack.job.JobEventListener;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.dependencytrack.workflow.WorkflowDao.NewWorkflowRun;
import org.dependencytrack.workflow.WorkflowDao.WorkflowRunTransition;
import org.dependencytrack.workflow.WorkflowDao.WorkflowStepRunTransition;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

// TODO: Metrics instrumentation
public class WorkflowEngine implements JobEventListener, Closeable {

    enum State {

        CREATED(1),  // 0
        STARTING(2), // 1
        RUNNING(3),  // 2
        STOPPING(4), // 3
        STOPPED(1);  // 4

        private final Set<Integer> allowedTransitions;

        State(final Integer... allowedTransitions) {
            this.allowedTransitions = Set.of(allowedTransitions);
        }

        private boolean canTransitionTo(final State newState) {
            return allowedTransitions.contains(newState.ordinal());
        }

        private boolean isCreatedOrStopped() {
            return equals(CREATED) || equals(STOPPED);
        }

        private void assertRunning() {
            if (!equals(RUNNING)) {
                throw new IllegalStateException(
                        "Engine must be in state %s, but is %s".formatted(RUNNING, this));
            }
        }

    }

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngine.class);
    private static final WorkflowEngine INSTANCE = new WorkflowEngine();

    private volatile State state = State.CREATED;
    private final ReentrantLock stateLock = new ReentrantLock();
    private final int jobEventQueueCapacity;
    private Queue<JobEvent> jobEventQueue;
    private ScheduledExecutorService jobEventFlushExecutor;
    private final Duration jobEventFlushInitialDelay;
    private final Duration jobEventFlushInterval;
    private final ReentrantLock jobEventFlushLock = new ReentrantLock();

    public WorkflowEngine() {
        // TODO: Find reasonable defaults for queue size and flush interval.
        this(100, Duration.ofSeconds(1), Duration.ofSeconds(5));
    }

    public WorkflowEngine(
            final int jobEventQueueCapacity,
            final Duration jobEventFlushInitialDelay,
            final Duration jobEventFlushInterval) {
        this.jobEventQueueCapacity = jobEventQueueCapacity;
        this.jobEventFlushInitialDelay = requireNonNull(jobEventFlushInitialDelay);
        this.jobEventFlushInterval = requireNonNull(jobEventFlushInterval);

    }

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

        this.jobEventQueue = new ConcurrentLinkedQueue<>();
        this.jobEventFlushExecutor = Executors.newSingleThreadScheduledExecutor(new BasicThreadFactory.Builder()
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .namingPattern("WorkflowEngine-JobEventFlusher-%d")
                .build());
        this.jobEventFlushExecutor.scheduleAtFixedRate(
                this::flushJobEvents,
                jobEventFlushInitialDelay.toMillis(),
                jobEventFlushInterval.toMillis(),
                TimeUnit.MILLISECONDS);

        setState(State.RUNNING);
    }

    // TODO: Listeners for workflow run state change?
    // TODO: Listeners for workflow step run state change?
    // TODO: Share transaction with JobEngine?

    public void deploy(final WorkflowSpec spec) {
        // TODO: Validate spec

        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            LOGGER.info("Deploying workflow %s/%d".formatted(spec.name(), spec.version()));
            final Workflow workflow = dao.createWorkflow(new NewWorkflow(spec.name(), spec.version()));
            if (workflow == null) {
                throw new IllegalStateException("Workflow %s/%d is already deployed".formatted(
                        spec.name(), spec.version()));
            }

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
        requireNonNull(options);
        state.assertRunning();

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
            final List<QueuedJob> queuedJobs = JobEngine.getInstance().enqueueAll(jobsToQueue);
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

    @Override
    public void onJobEvent(final JobEvent event) {
        state.assertRunning();

        final boolean isRelevant = event instanceof JobCompletedEvent
                                   || event instanceof JobFailedEvent
                                   || event instanceof JobStartedEvent;
        if (isRelevant && event.job().workflowStepRunId() != null) {
            jobEventQueue.add(event);
        }
    }

    @Override
    public void close() throws IOException {
        if (state.isCreatedOrStopped()) {
            return;
        }

        LOGGER.info("Stopping");
        setState(State.STOPPING);

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
        jobEventQueue.clear();
        jobEventQueue = null;
        jobEventFlushExecutor = null;
        setState(State.STOPPED);
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
            LOGGER.debug("No job events to flush");
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
                        stepRunId,
                        WorkflowStepRunStatus.COMPLETED,
                        /* failureReason */ null));
                case JobFailedEvent failedEvent -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId,
                        WorkflowStepRunStatus.FAILED,
                        "Job failed: %s".formatted(failedEvent.failureReason())));
                case JobStartedEvent ignored -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId,
                        WorkflowStepRunStatus.RUNNING,
                        /* failureReason */ null));
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

            LOGGER.debug("Transitioned status of %d workflow step runs".formatted(transitionedStepRuns.size()));
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
                if (LOGGER.isDebugEnabled()) {
                    for (final WorkflowRun completedWorkflowRun : completedWorkflowRuns) {
                        LOGGER.debug("Completed %s".formatted(completedWorkflowRun));
                    }
                }
            }

            final List<WorkflowStepRun> failedStepRuns = stepRunsByStatus.get(WorkflowStepRunStatus.FAILED);
            if (failedStepRuns != null) {
                final List<WorkflowStepRun> cancelledStepRuns = dao.cancelDependantStepRuns(failedStepRuns);
                for (final WorkflowStepRun cancelledStepRun : cancelledStepRuns) {
                    LOGGER.warn("Cancelled %s".formatted(cancelledStepRun));
                }

                final List<WorkflowRun> failedWorkflowRuns = dao.transitionWorkflowRuns(failedStepRuns.stream()
                        .map(stepRun -> new WorkflowRunTransition(
                                stepRun.workflowRunId(),
                                WorkflowRunStatus.FAILED))
                        .toList());
                for (final WorkflowRun failedWorkflowRun : failedWorkflowRuns) {
                    LOGGER.warn("Failed %s".formatted(failedWorkflowRun));
                }
            }
        });

        if (!jobsToQueue.isEmpty()) {
            final List<QueuedJob> queuedJobs = JobEngine.getInstance().enqueueAll(jobsToQueue);
            if (LOGGER.isDebugEnabled()) {
                for (final QueuedJob queuedJob : queuedJobs) {
                    LOGGER.debug("Queued %s".formatted(queuedJob));
                }
            }
        }
    }

    State state() {
        return state;
    }

    private void setState(final State newState) {
        stateLock.lock();
        try {
            if (this.state.canTransitionTo(newState)) {
                this.state = newState;
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from state %s to %s".formatted(this.state, newState));
        } finally {
            stateLock.unlock();
        }
    }

}
