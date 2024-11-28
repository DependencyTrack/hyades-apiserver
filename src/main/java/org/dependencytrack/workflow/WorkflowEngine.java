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

import alpine.Config;
import alpine.common.metrics.Metrics;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.v1alpha1.RunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.TaskAction.AbandonActivityTaskAction;
import org.dependencytrack.workflow.TaskAction.AbandonWorkflowTaskAction;
import org.dependencytrack.workflow.TaskAction.CompleteActivityTaskAction;
import org.dependencytrack.workflow.TaskAction.CompleteWorkflowTaskAction;
import org.dependencytrack.workflow.annotation.Activity;
import org.dependencytrack.workflow.annotation.Workflow;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.workflow.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventInboxRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventLogRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.PolledInboxEvent;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRowUpdate;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class WorkflowEngine implements Closeable {

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

        boolean isStoppingOrStopped() {
            return equals(STOPPING) || equals(STOPPED);
        }

        boolean isNotStoppingOrStopped() {
            return !isStoppingOrStopped();
        }

        private void assertRunning() {
            if (!equals(RUNNING)) {
                throw new IllegalStateException(
                        "Engine must be in state %s, but is %s".formatted(RUNNING, this));
            }
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngine.class);
    private static final Pattern WORKFLOW_NAME_PATTERN = Pattern.compile("^[\\w-]+");
    private static final Pattern ACTIVITY_NAME_PATTERN = WORKFLOW_NAME_PATTERN;
    private static final WorkflowEngine INSTANCE = new WorkflowEngine();

    private final UUID instanceId = UUID.randomUUID();
    private final ReentrantLock stateLock = new ReentrantLock();
    private State state = State.CREATED;
    private ExecutorService dispatcherExecutor;
    private Map<String, ExecutorService> executorServiceByName;
    private Buffer<NewExternalEvent> externalEventBuffer;
    private Buffer<TaskAction> taskActionBuffer;

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

        externalEventBuffer = new Buffer<>(
                "workflow-external-event",
                this::flushExternalEvents,
                Duration.ofMillis(10),
                100);
        externalEventBuffer.start();

        // The buffer's flush interval should be long enough to allow
        // for more than one task result to be included, but short enough
        // to not block task execution unnecessarily. In a worst-case scenario,
        // task workers can be blocked for an entire flush interval.
        taskActionBuffer = new Buffer<>(
                "workflow-task-action",
                this::processTaskActions,
                /* flushInterval */ Duration.ofMillis(5),
                /* maxBatchSize */ 100);
        taskActionBuffer.start();

        executorServiceByName = new HashMap<>();

        dispatcherExecutor = Executors.newThreadPerTaskExecutor(
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-TaskDispatcher-%d")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(dispatcherExecutor, "WorkflowEngine-TaskDispatcher", null)
                    .bindTo(Metrics.getRegistry());
        }

        setState(State.RUNNING);
    }

    @Override
    public void close() throws IOException {
        setState(State.STOPPING);

        LOGGER.debug("Waiting for task dispatcher to stop");
        dispatcherExecutor.shutdown();
        try {
            dispatcherExecutor.awaitTermination(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        dispatcherExecutor = null;

        LOGGER.debug("Waiting for task executors to stop");
        for (final ExecutorService executorService : executorServiceByName.values()) {
            executorService.shutdown();
            try {
                executorService.awaitTermination(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        executorServiceByName = null;

        externalEventBuffer.close();
        externalEventBuffer = null;

        taskActionBuffer.close();
        taskActionBuffer = null;

        setState(State.STOPPED);
    }

    public <A, R> void registerWorkflowRunner(
            final WorkflowRunner<A, R> workflowRunner,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        requireNonNull(workflowRunner, "workflowRunner must not be null");

        final var workflowAnnotation = workflowRunner.getClass().getAnnotation(Workflow.class);
        if (workflowAnnotation == null) {
            throw new IllegalArgumentException("workflowRunner must be annotated with @Workflow");
        }

        registerWorkflowRunner(workflowAnnotation.name(), maxConcurrency, argumentConverter, resultConverter, workflowRunner);
    }

    <A, R> void registerWorkflowRunner(
            final String workflowName,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final WorkflowRunner<A, R> workflowRunner) {
        state.assertRunning();
        requireNonNull(workflowName, "workflowName must not be null");
        requireValidWorkflowName(workflowName);
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(workflowRunner, "workflowRunner must not be null");

        final String executorName = "workflow:%s".formatted(workflowName);
        if (executorServiceByName.containsKey(executorName)) {
            throw new IllegalStateException("Workflow %s is already registered".formatted(workflowName));
        }

        final ExecutorService executorService = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .name("WorkflowEngine-WorkflowRunner-" + workflowName + "-", 0)
                        .factory());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-WorkflowRunner-" + workflowName, null)
                    .bindTo(Metrics.getRegistry());
        }
        executorServiceByName.put(executorName, executorService);

        final var taskProcessor = new WorkflowTaskProcessor<>(
                this, workflowName, workflowRunner, argumentConverter, resultConverter);

        dispatcherExecutor.execute(new TaskDispatcher<>(this, executorService, taskProcessor, maxConcurrency));
    }

    public <A, R> void registerActivityRunner(
            final ActivityRunner<A, R> activityRunner,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        requireNonNull(activityRunner, "activityRunner must not be null");

        final var activityAnnotation = activityRunner.getClass().getAnnotation(Activity.class);
        if (activityAnnotation == null) {
            throw new IllegalArgumentException("activityRunner class must be annotated with @Activity");
        }

        registerActivityRunner(activityAnnotation.name(), maxConcurrency, argumentConverter, resultConverter, activityRunner);
    }

    <A, R> void registerActivityRunner(
            final String activityName,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final ActivityRunner<A, R> activityRunner) {
        state.assertRunning();
        requireNonNull(activityName, "activityName must not be null");
        requireValidActivityName(activityName);
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(activityRunner, "activityRunner must not be null");

        final String executorName = "activity:%s".formatted(activityName);
        if (executorServiceByName.containsKey(executorName)) {
            throw new IllegalStateException("Activity %s is already registered".formatted(activityName));
        }

        // TODO: Use virtual threads?
        final ExecutorService executorService = Executors.newFixedThreadPool(maxConcurrency,
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-ActivityRunner-" + activityName + "-%d")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-ActivityRunner-" + activityName, null)
                    .bindTo(Metrics.getRegistry());
        }
        executorServiceByName.put(executorName, executorService);

        final var taskProcessor = new ActivityTaskProcessor<>(
                this, activityName, activityRunner, argumentConverter, resultConverter);

        dispatcherExecutor.execute(new TaskDispatcher<>(this, executorService, taskProcessor, maxConcurrency));
    }

    public List<UUID> scheduleWorkflowRuns(final Collection<ScheduleWorkflowRunOptions> options) {
        state.assertRunning();

        final var now = Timestamps.now();
        final var newWorkflowRunRows = new ArrayList<NewWorkflowRunRow>(options.size());
        final var newInboxEventRows = new ArrayList<NewWorkflowEventInboxRow>(options.size());
        for (final ScheduleWorkflowRunOptions option : options) {
            final var runId = UUID.randomUUID();
            newWorkflowRunRows.add(new NewWorkflowRunRow(
                    runId, option.workflowName(), option.workflowVersion(), option.argument()));
            newInboxEventRows.add(new NewWorkflowEventInboxRow(runId, null,
                    WorkflowEvent.newBuilder()
                            .setId(-1)
                            .setTimestamp(now)
                            .setRunStarted(RunStarted.newBuilder()
                                    .setWorkflowName(option.workflowName())
                                    .setWorkflowVersion(option.workflowVersion())
                                    .build())
                            .build()));
        }

        return inJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final List<WorkflowRunRow> createdRuns = dao.createWorkflowRuns(newWorkflowRunRows);
            assert createdRuns.size() == newWorkflowRunRows.size();

            final int createdInboxEvents = dao.createInboxEvents(newInboxEventRows);
            assert createdInboxEvents == newInboxEventRows.size();

            return createdRuns.stream()
                    .map(WorkflowRunRow::id)
                    .toList();
        });
    }

    public UUID scheduleWorkflowRun(final ScheduleWorkflowRunOptions options) {
        final List<UUID> scheduledRunIds = scheduleWorkflowRuns(List.of(options));
        if (scheduledRunIds.isEmpty()) {
            return null;
        }

        return scheduledRunIds.getFirst();
    }

    public CompletableFuture<Void> sendExternalEvent(
            final UUID workflowRunId,
            final String eventId,
            final WorkflowPayload content) {
        state.assertRunning();

        try {
            return externalEventBuffer.add(new NewExternalEvent(workflowRunId, eventId, content));
        } catch (InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }
    }

    private void flushExternalEvents(final List<NewExternalEvent> externalEvents) {
        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final var now = Timestamps.now();
            dao.createInboxEvents(externalEvents.stream()
                    .map(externalEvent -> new NewWorkflowEventInboxRow(
                            externalEvent.workflowRunId(),
                            null,
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(now)
                                    .setExternalEventReceived(ExternalEventReceived.newBuilder()
                                            .setId(externalEvent.eventId())
                                            .build())
                                    .build()
                    ))
                    .toList());
        });
    }

    List<WorkflowTask> pollWorkflowTasks(final String workflowName, final int limit) {
        return inJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final Map<UUID, PolledWorkflowRunRow> polledRunById =
                    dao.pollAndLockWorkflowRuns(this.instanceId, workflowName, Duration.ofSeconds(30), limit);
            if (polledRunById.isEmpty()) {
                return Collections.emptyList();
            }

            final Map<UUID, List<WorkflowEvent>> eventLogByRunId =
                    dao.getWorkflowEventLogs(polledRunById.keySet());

            final Map<UUID, List<PolledInboxEvent>> polledInboxEventsByRunId =
                    dao.pollAndLockInboxEvents(this.instanceId, polledRunById.keySet());

            return polledRunById.values().stream()
                    .map(polledRun -> {
                        final List<WorkflowEvent> eventLog = eventLogByRunId.getOrDefault(
                                polledRun.id(), Collections.emptyList());

                        final List<PolledInboxEvent> polledInboxEvents =
                                polledInboxEventsByRunId.getOrDefault(polledRun.id(), Collections.emptyList());

                        int maxDequeueCount = 0;
                        final var inboxEvents = new ArrayList<WorkflowEvent>(polledInboxEvents.size());
                        for (final PolledInboxEvent polledEvent : polledInboxEvents) {
                            maxDequeueCount = Math.max(maxDequeueCount, polledEvent.dequeueCount());
                            inboxEvents.add(polledEvent.event());
                        }

                        return new WorkflowTask(
                                polledRun.id(),
                                polledRun.workflowName(),
                                polledRun.workflowVersion(),
                                polledRun.priority(),
                                polledRun.argument(),
                                maxDequeueCount,
                                eventLog,
                                inboxEvents);
                    })
                    .toList();
        });
    }

    CompletableFuture<Void> abandonWorkflowTask(
            final WorkflowTask task) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new AbandonWorkflowTaskAction(task));
    }

    private void abandonWorkflowTask(final WorkflowDao dao, final WorkflowTask task) {
        // TODO: Make this configurable.
        final IntervalFunction abandonDelayIntervalFunction = IntervalFunction.ofExponentialBackoff(
                Duration.ofSeconds(5), 1.5, Duration.ofMinutes(30));
        final Duration abandonDelay = Duration.ofMillis(abandonDelayIntervalFunction.apply(task.attempt() + 1));

        final int unlockedEvents = dao.unlockInboxEvents(this.instanceId, task.workflowRunId(), abandonDelay);
        assert unlockedEvents == task.inboxEvents().size();

        final int unlockedWorkflowRuns = dao.unlockWorkflowRun(this.instanceId, task.workflowRunId());
        assert unlockedWorkflowRuns == 1;
    }

    CompletableFuture<Void> completeWorkflowTask(
            final WorkflowRun workflowRun) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new CompleteWorkflowTaskAction(workflowRun));
    }

    private void completeWorkflowTasks(final WorkflowDao dao, final Collection<WorkflowRun> workflowRuns) {
        final var newEventLogEntries = new ArrayList<NewWorkflowEventLogRow>(workflowRuns.size() * 2);
        final var newInboxEvents = new ArrayList<NewWorkflowEventInboxRow>(workflowRuns.size() * 2);
        final var newWorkflowRuns = new ArrayList<NewWorkflowRunRow>();
        final var newActivityTasks = new ArrayList<NewActivityTaskRow>();

        final int updatedRuns = dao.updateWorkflowRuns(this.instanceId,
                workflowRuns.stream()
                        .map(run -> new WorkflowRunRowUpdate(
                                run.workflowRunId(),
                                run.status(),
                                run.customStatus().orElse(null),
                                run.argument().orElse(null),
                                run.result().orElse(null),
                                run.failureDetails().orElse(null),
                                run.createdAt().orElse(null),
                                run.updatedAt().orElse(null),
                                run.completedAt().orElse(null)))
                        .toList());
        assert updatedRuns == workflowRuns.size();

        for (final WorkflowRun workflowRun : workflowRuns) {
            int sequenceNumber = workflowRun.eventLog().size();
            for (final WorkflowEvent newEvent : workflowRun.inboxEvents()) {
                newEventLogEntries.add(new NewWorkflowEventLogRow(
                        workflowRun.workflowRunId(),
                        sequenceNumber++,
                        newEvent));
            }

            for (final WorkflowEvent newEvent : workflowRun.pendingTimerFiredEvents()) {
                newInboxEvents.add(new NewWorkflowEventInboxRow(
                        workflowRun.workflowRunId(),
                        toInstant(newEvent.getTimerFired().getElapseAt()),
                        newEvent));
            }

            for (final WorkflowMessage message : workflowRun.pendingWorkflowMessages()) {
                // If the outbound message is a RunStarted event, the recipient
                // workflow run will need to be created first.
                if (message.event().hasRunStarted()) {
                    newWorkflowRuns.add(new NewWorkflowRunRow(
                            message.recipientRunId(),
                            message.event().getRunStarted().getWorkflowName(),
                            message.event().getRunStarted().getWorkflowVersion(),
                            message.event().getRunStarted().hasArgument()
                                    ? message.event().getRunStarted().getArgument()
                                    : null));
                }
                newInboxEvents.add(new NewWorkflowEventInboxRow(
                        message.recipientRunId(),
                        toInstant(message.event().getTimestamp()),
                        message.event()));
            }

            for (final WorkflowEvent newEvent : workflowRun.pendingActivityTaskScheduledEvents()) {
                newActivityTasks.add(new NewActivityTaskRow(
                        workflowRun.workflowRunId(),
                        newEvent.getId(),
                        newEvent.getActivityTaskScheduled().getName(),
                        newEvent.getActivityTaskScheduled().hasPriority()
                                ? newEvent.getActivityTaskScheduled().getPriority()
                                : null,
                        newEvent.getActivityTaskScheduled().hasArgument()
                                ? newEvent.getActivityTaskScheduled().getArgument()
                                : null,
                        newEvent.getActivityTaskScheduled().hasScheduledFor()
                                ? toInstant(newEvent.getActivityTaskScheduled().getScheduledFor())
                                : null));
            }
        }

        if (!newEventLogEntries.isEmpty()) {
            dao.createWorkflowEventLogEntries(newEventLogEntries);
        }

        if (!newWorkflowRuns.isEmpty()) {
            final List<WorkflowRunRow> createdRuns = dao.createWorkflowRuns(newWorkflowRuns);
            assert createdRuns.size() == newWorkflowRuns.size();
        }

        if (!newInboxEvents.isEmpty()) {
            final int createdInboxEvents = dao.createInboxEvents(newInboxEvents);
            assert createdInboxEvents == newInboxEvents.size();
        }

        if (!newActivityTasks.isEmpty()) {
            final int createdActivityTasks = dao.createActivityTasks(newActivityTasks);
            assert createdActivityTasks == newActivityTasks.size();
        }

        final int deletedInboxEvents = dao.deleteLockedInboxEvents(
                this.instanceId, workflowRuns.stream().map(WorkflowRun::workflowRunId).toList());
        assert deletedInboxEvents >= workflowRuns.size();
    }

    List<ActivityTask> pollActivityTasks(final String activityName, final int limit) {
        return inJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            return dao.pollAndLockActivityTasks(this.instanceId, activityName, Duration.ofSeconds(30), limit).stream()
                    .map(polledTask -> new ActivityTask(
                            polledTask.workflowRunId(),
                            polledTask.scheduledEventId(),
                            polledTask.activityName(),
                            polledTask.argument(),
                            polledTask.lockedUntil()))
                    .toList();
        });
    }

    CompletableFuture<Void> abandonActivityTask(
            final ActivityTask task) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new AbandonActivityTaskAction(task));
    }

    private void abandonActivityTask(final WorkflowDao dao, final ActivityTask task) {
        final int unlockedTasks = dao.unlockActivityTasks(this.instanceId,
                Stream.of(task)
                        .map(t -> new ActivityTaskId(t.workflowRunId(), t.sequenceNumber()))
                        .toList());
        assert unlockedTasks == 1;
    }

    CompletableFuture<Void> completeActivityTask(
            final ActivityTask task, final WorkflowEvent event) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new CompleteActivityTaskAction(task, event));
    }

    private void completeActivityTask(final WorkflowDao dao, final ActivityTask task, final WorkflowEvent event) {
        final int createdInboxEvents = dao.createInboxEvents(List.of(new NewWorkflowEventInboxRow(task.workflowRunId(), null, event)));
        assert createdInboxEvents == 1;

        final int deletedTasks = dao.deleteLockedActivityTasks(this.instanceId,
                Stream.of(task)
                        .map(t -> new ActivityTaskId(t.workflowRunId(), t.sequenceNumber()))
                        .toList());
        assert deletedTasks == 1;
    }

    Instant heartbeatActivityTask(final ActivityTaskId taskId) {
        final Instant newLockTimeout = inJdbiTransaction(
                handle -> new WorkflowDao(handle).extendActivityTaskLock(
                        this.instanceId, taskId, Duration.ofSeconds(30)));
        assert newLockTimeout != null;
        return newLockTimeout;
    }

    private void processTaskActions(final List<TaskAction> actions) {
        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            // TODO: Group by action and process them using batch queries.
            final var runsToComplete = new ArrayList<WorkflowRun>();
            for (final TaskAction action : actions) {
                switch (action) {
                    case AbandonActivityTaskAction a -> abandonActivityTask(dao, a.task());
                    case CompleteActivityTaskAction c -> completeActivityTask(dao, c.task(), c.event());
                    case AbandonWorkflowTaskAction a -> abandonWorkflowTask(dao, a.task());
                    case CompleteWorkflowTaskAction c -> runsToComplete.add(c.workflowRun());
                }
            }

            if (!runsToComplete.isEmpty()) {
                completeWorkflowTasks(dao, runsToComplete);
            }
        });
    }

    WorkflowRunRow getWorkflowRun(final UUID workflowRunId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT *
                          FROM "WORKFLOW_RUN"
                         WHERE "ID" = :id
                        """)
                .bind("id", workflowRunId)
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .findOne()
                .orElse(null));
    }

    List<WorkflowEvent> getWorkflowEventLog(final UUID runId) {
        return withJdbiHandle(handle -> new WorkflowDao(handle).getWorkflowRunEventLog(runId));
    }

    State state() {
        return state;
    }

    private void setState(final State newState) {
        stateLock.lock();
        try {
            if (this.state == newState) {
                return;
            }

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

    static Instant toInstant(final Timestamp timestamp) {
        return Instant.ofEpochSecond(0L, Timestamps.toNanos(timestamp));
    }

    static Timestamp toTimestamp(final Instant instant) {
        return Timestamps.fromDate(Date.from(instant));
    }

    private static void requireValidWorkflowName(final String workflowName) {
        if (!WORKFLOW_NAME_PATTERN.matcher(workflowName).matches()) {
            throw new IllegalArgumentException("workflowName must match " + WORKFLOW_NAME_PATTERN.pattern());
        }
    }

    private static void requireValidActivityName(final String activityName) {
        if (!ACTIVITY_NAME_PATTERN.matcher(activityName).matches()) {
            throw new IllegalArgumentException("activityName must match " + ACTIVITY_NAME_PATTERN.pattern());
        }
    }

}
