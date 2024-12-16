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
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskFailed;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.v1alpha1.RunCancelled;
import org.dependencytrack.proto.workflow.v1alpha1.RunResumed;
import org.dependencytrack.proto.workflow.v1alpha1.RunScheduled;
import org.dependencytrack.proto.workflow.v1alpha1.RunSuspended;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.TaskAction.AbandonActivityTaskAction;
import org.dependencytrack.workflow.TaskAction.AbandonWorkflowTaskAction;
import org.dependencytrack.workflow.TaskAction.CompleteActivityTaskAction;
import org.dependencytrack.workflow.TaskAction.CompleteWorkflowTaskAction;
import org.dependencytrack.workflow.TaskAction.FailActivityTaskAction;
import org.dependencytrack.workflow.annotation.Activity;
import org.dependencytrack.workflow.annotation.Workflow;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.persistence.model.DeleteInboxEventsCommand;
import org.dependencytrack.workflow.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunInboxRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunJournalRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowConcurrencyGroupRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRowUpdate;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_BUFFER_EXTERNAL_EVENT_FLUSH_INTERVAL_MS;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_BUFFER_EXTERNAL_EVENT_MAX_BATCH_SIZE;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_BUFFER_TASK_ACTION_FLUSH_INTERVAL_MS;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_BUFFER_TASK_ACTION_MAX_BATCH_SIZE;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS;
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
    private ExecutorService taskDispatcherExecutor;
    private Duration taskDispatcherMinPollInterval;
    private Map<String, ExecutorService> executorServiceByName;
    private Buffer<NewExternalEvent> externalEventBuffer;
    private Buffer<TaskAction> taskActionBuffer;

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

        // TODO: Decouple from Alpine's config to make the engine more modular.
        //  Use a dedicated configuration class instead that DT can populate on startup.
        final Duration externalEventBufferFlushInterval = Duration.ofMillis(Config.getInstance()
                .getPropertyAsInt(WORKFLOW_ENGINE_BUFFER_EXTERNAL_EVENT_FLUSH_INTERVAL_MS));
        final int externalEventBufferMaxBatchSize = Config.getInstance()
                .getPropertyAsInt(WORKFLOW_ENGINE_BUFFER_EXTERNAL_EVENT_MAX_BATCH_SIZE);

        externalEventBuffer = new Buffer<>(
                "workflow-external-event",
                this::flushExternalEvents,
                externalEventBufferFlushInterval,
                externalEventBufferMaxBatchSize);
        externalEventBuffer.start();

        // The buffer's flush interval should be long enough to allow
        // for more than one task result to be included, but short enough
        // to not block task execution unnecessarily. In a worst-case scenario,
        // task workers can be blocked for an entire flush interval.
        // TODO: Separate buffer for workflow actions from buffer for activity actions?
        //  Workflow tasks usually complete a lot faster than activity tasks.
        final Duration taskActionBufferFlushInterval = Duration.ofMillis(Config.getInstance()
                .getPropertyAsInt(WORKFLOW_ENGINE_BUFFER_TASK_ACTION_FLUSH_INTERVAL_MS));
        final int taskActionBufferMaxBatchSize = Config.getInstance()
                .getPropertyAsInt(WORKFLOW_ENGINE_BUFFER_TASK_ACTION_MAX_BATCH_SIZE);

        taskActionBuffer = new Buffer<>(
                "workflow-task-action",
                this::processTaskActions,
                taskActionBufferFlushInterval,
                taskActionBufferMaxBatchSize);
        taskActionBuffer.start();

        executorServiceByName = new HashMap<>();

        taskDispatcherExecutor = Executors.newThreadPerTaskExecutor(
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-TaskDispatcher-%d")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(taskDispatcherExecutor, "WorkflowEngine-TaskDispatcher", null)
                    .bindTo(Metrics.getRegistry());
        }

        taskDispatcherMinPollInterval = Duration.ofMillis(Config.getInstance()
                .getPropertyAsInt(WORKFLOW_ENGINE_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS));

        setState(State.RUNNING);
    }

    @Override
    public void close() throws IOException {
        setState(State.STOPPING);

        LOGGER.debug("Waiting for task dispatcher to stop");
        taskDispatcherExecutor.close();
        taskDispatcherExecutor = null;

        LOGGER.debug("Waiting for task executors to stop");
        executorServiceByName.values().forEach(ExecutorService::close);
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
            final PayloadConverter<R> resultConverter,
            final Duration taskLockTimeout) {
        requireNonNull(workflowRunner, "workflowRunner must not be null");

        final var workflowAnnotation = workflowRunner.getClass().getAnnotation(Workflow.class);
        if (workflowAnnotation == null) {
            throw new IllegalArgumentException("workflowRunner must be annotated with @Workflow");
        }

        registerWorkflowRunner(workflowAnnotation.name(), maxConcurrency,
                argumentConverter, resultConverter, taskLockTimeout, workflowRunner);
    }

    <A, R> void registerWorkflowRunner(
            final String workflowName,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration taskLockTimeout,
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
                this, workflowName, workflowRunner, argumentConverter, resultConverter, taskLockTimeout);

        taskDispatcherExecutor.execute(new TaskDispatcher<>(
                this, executorService, taskProcessor, maxConcurrency, taskDispatcherMinPollInterval));
    }

    public <A, R> void registerActivityRunner(
            final ActivityRunner<A, R> activityRunner,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration taskLockTimeout) {
        requireNonNull(activityRunner, "activityRunner must not be null");

        final var activityAnnotation = activityRunner.getClass().getAnnotation(Activity.class);
        if (activityAnnotation == null) {
            throw new IllegalArgumentException("activityRunner class must be annotated with @Activity");
        }

        registerActivityRunner(activityAnnotation.name(), maxConcurrency,
                argumentConverter, resultConverter, taskLockTimeout, activityRunner);
    }

    <A, R> void registerActivityRunner(
            final String activityName,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration taskLockTimeout,
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

        final ExecutorService executorService = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .name("WorkflowEngine-ActivityRunner-" + activityName + "-", 0)
                        .factory());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-ActivityRunner-" + activityName, null)
                    .bindTo(Metrics.getRegistry());
        }
        executorServiceByName.put(executorName, executorService);

        final var taskProcessor = new ActivityTaskProcessor<>(
                this, activityName, activityRunner, argumentConverter, resultConverter, taskLockTimeout);

        taskDispatcherExecutor.execute(new TaskDispatcher<>(
                this, executorService, taskProcessor, maxConcurrency, taskDispatcherMinPollInterval));
    }

    public List<UUID> scheduleWorkflowRuns(final Collection<ScheduleWorkflowRunOptions> options) {
        state.assertRunning();

        final var now = Timestamps.now();
        final var newWorkflowRunRows = new ArrayList<NewWorkflowRunRow>(options.size());
        final var newInboxEventRows = new ArrayList<NewWorkflowRunInboxRow>(options.size());
        final var nextRunIdByConcurrencyGroupId = new HashMap<String, UUID>();
        for (final ScheduleWorkflowRunOptions option : options) {
            final UUID runId = randomUUIDv7();
            newWorkflowRunRows.add(new NewWorkflowRunRow(
                    runId,
                    option.workflowName(),
                    option.workflowVersion(),
                    option.concurrencyGroupId(),
                    option.priority(),
                    option.tags()));

            final var runScheduledBuilder = RunScheduled.newBuilder()
                    .setWorkflowName(option.workflowName())
                    .setWorkflowVersion(option.workflowVersion());
            if (option.concurrencyGroupId() != null) {
                runScheduledBuilder.setConcurrencyGroupId(option.concurrencyGroupId());
            }
            if (option.priority() != null) {
                runScheduledBuilder.setPriority(option.priority());
            }
            if (option.tags() != null) {
                runScheduledBuilder.addAllTags(option.tags());
            }
            if (option.argument() != null) {
                runScheduledBuilder.setArgument(option.argument());
            }

            newInboxEventRows.add(new NewWorkflowRunInboxRow(runId, null,
                    WorkflowEvent.newBuilder()
                            .setId(-1)
                            .setTimestamp(now)
                            .setRunScheduled(runScheduledBuilder.build())
                            .build()));

            if (option.concurrencyGroupId() != null) {
                nextRunIdByConcurrencyGroupId.compute(option.concurrencyGroupId(), (ignored, previous) -> {
                    if (previous == null) {
                        return runId;
                    }

                    return runId.compareTo(previous) < 0 ? runId : previous;
                });
            }
        }

        final List<WorkflowConcurrencyGroupRow> newConcurrencyGroupRows =
                nextRunIdByConcurrencyGroupId.entrySet().stream()
                        .map(entry -> new WorkflowConcurrencyGroupRow(
                                /* id */ entry.getKey(),
                                /* nextRunId */ entry.getValue()))
                        .toList();

        return inJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final List<UUID> createdRunIds = dao.createRuns(newWorkflowRunRows);
            assert createdRunIds.size() == newWorkflowRunRows.size();

            final int createdInboxEvents = dao.createRunInboxEvents(newInboxEventRows);
            assert createdInboxEvents == newInboxEventRows.size();

            if (!newConcurrencyGroupRows.isEmpty()) {
                dao.maybeCreateConcurrencyGroups(newConcurrencyGroupRows);
            }

            return createdRunIds;
        });
    }

    public UUID scheduleWorkflowRun(final ScheduleWorkflowRunOptions options) {
        final List<UUID> scheduledRunIds = scheduleWorkflowRuns(List.of(options));
        if (scheduledRunIds.isEmpty()) {
            return null;
        }

        return scheduledRunIds.getFirst();
    }

    public void cancelWorkflowRun(final UUID runId, final String reason) {
        final var cancellationEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunCancelled(RunCancelled.newBuilder()
                        .setReason(reason)
                        .build())
                .build();

        // TODO: Assert that current run status is not terminal,
        //  and no runCancelled event is pending already.

        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new NewWorkflowRunInboxRow(runId, null, cancellationEvent)));
            assert createdInboxEvents == 1;
        });
    }

    public void suspendWorkflowRun(final UUID runId) {
        final var suspensionEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunSuspended(RunSuspended.newBuilder().build())
                .build();

        // TODO: Assert that current run status is not suspended or terminal,
        //  and no runSuspended event is pending already.

        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new NewWorkflowRunInboxRow(runId, null, suspensionEvent)));
            assert createdInboxEvents == 1;
        });
    }

    public void resumeWorkflowRun(final UUID runId) {
        final var resumeEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunResumed(RunResumed.newBuilder().build())
                .build();

        // TODO: Assert that current run status is suspended,
        //  and no runResumed event is pending already.

        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new NewWorkflowRunInboxRow(runId, null, resumeEvent)));
            assert createdInboxEvents == 1;
        });
    }

    public CompletableFuture<Void> sendExternalEvent(
            final UUID workflowRunId,
            final String eventId,
            final WorkflowPayload content) {
        state.assertRunning();

        // TODO: Write content to file storage instead. We don't know how large the payload is.

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
            dao.createRunInboxEvents(externalEvents.stream()
                    .map(externalEvent -> new NewWorkflowRunInboxRow(
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

    List<WorkflowTask> pollWorkflowTasks(final String workflowName, final int limit, final Duration taskLockTimeout) {
        return inJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final Map<UUID, PolledWorkflowRunRow> polledRunById =
                    dao.pollAndLockRuns(this.instanceId, workflowName, taskLockTimeout, limit);
            if (polledRunById.isEmpty()) {
                return Collections.emptyList();
            }

            final Map<UUID, PolledWorkflowEvents> polledEventsByRunId =
                    dao.pollRunEvents(this.instanceId, polledRunById.keySet());

            return polledRunById.values().stream()
                    .map(polledRun -> {
                        final PolledWorkflowEvents polledEvents = polledEventsByRunId.get(polledRun.id());

                        return new WorkflowTask(
                                polledRun.id(),
                                polledRun.workflowName(),
                                polledRun.workflowVersion(),
                                polledRun.concurrencyGroupId(),
                                polledRun.priority(),
                                polledRun.tags(),
                                polledEvents.maxInboxEventDequeueCount(),
                                polledEvents.journal(),
                                polledEvents.inbox());
                    })
                    .toList();
        });
    }

    CompletableFuture<Void> abandonWorkflowTask(
            final WorkflowTask task) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new AbandonWorkflowTaskAction(task));
    }

    // TODO: Make this a batch operation.
    private void abandonWorkflowTask(final WorkflowDao dao, final WorkflowTask task) {
        // TODO: Make this configurable.
        final IntervalFunction abandonDelayIntervalFunction = IntervalFunction.ofExponentialBackoff(
                Duration.ofSeconds(5), 1.5, Duration.ofMinutes(30));
        final Duration abandonDelay = Duration.ofMillis(abandonDelayIntervalFunction.apply(task.attempt() + 1));

        final int unlockedEvents = dao.unlockRunInboxEvents(this.instanceId, task.workflowRunId(), abandonDelay);
        assert unlockedEvents == task.inbox().size();

        final int unlockedWorkflowRuns = dao.unlockRun(this.instanceId, task.workflowRunId());
        assert unlockedWorkflowRuns == 1;
    }

    CompletableFuture<Void> completeWorkflowTask(
            final WorkflowRun workflowRun) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new CompleteWorkflowTaskAction(workflowRun));
    }

    private void completeWorkflowTasksInternal(
            final WorkflowDao dao,
            final Collection<CompleteWorkflowTaskAction> actions) {
        final var newJournalEntries = new ArrayList<NewWorkflowRunJournalRow>(actions.size() * 2);
        final var newInboxEvents = new ArrayList<NewWorkflowRunInboxRow>(actions.size() * 2);
        final var newWorkflowRuns = new ArrayList<NewWorkflowRunRow>();
        final var newActivityTasks = new ArrayList<NewActivityTaskRow>();
        final var nextRunIdByNewConcurrencyGroupId = new HashMap<String, UUID>();
        final var concurrencyGroupsToUpdate = new HashSet<String>();

        final int updatedRuns = dao.updateRuns(this.instanceId,
                actions.stream()
                        .map(CompleteWorkflowTaskAction::workflowRun)
                        .map(run -> new WorkflowRunRowUpdate(
                                run.workflowRunId(),
                                run.status(),
                                run.customStatus().orElse(null),
                                run.createdAt().orElse(null),
                                run.updatedAt().orElse(null),
                                run.startedAt().orElse(null),
                                run.completedAt().orElse(null)))
                        .toList());
        assert updatedRuns == actions.size();

        for (final CompleteWorkflowTaskAction action : actions) {
            final WorkflowRun workflowRun = action.workflowRun();

            int sequenceNumber = workflowRun.journal().size();
            for (final WorkflowEvent newEvent : workflowRun.inbox()) {
                newJournalEntries.add(new NewWorkflowRunJournalRow(
                        workflowRun.workflowRunId(),
                        sequenceNumber++,
                        newEvent));
            }

            for (final WorkflowEvent newEvent : workflowRun.pendingTimerFiredEvents()) {
                newInboxEvents.add(new NewWorkflowRunInboxRow(
                        workflowRun.workflowRunId(),
                        toInstant(newEvent.getTimerFired().getElapseAt()),
                        newEvent));
            }

            for (final WorkflowRunMessage message : workflowRun.pendingWorkflowMessages()) {
                // If the outbound message is a RunScheduled event, the recipient
                // workflow run will need to be created first.
                if (message.event().hasRunScheduled()) {
                    newWorkflowRuns.add(new NewWorkflowRunRow(
                            message.recipientRunId(),
                            message.event().getRunScheduled().getWorkflowName(),
                            message.event().getRunScheduled().getWorkflowVersion(),
                            message.event().getRunScheduled().hasConcurrencyGroupId()
                                    ? message.event().getRunScheduled().getConcurrencyGroupId()
                                    : null,
                            message.event().getRunScheduled().hasPriority()
                                    ? message.event().getRunScheduled().getPriority()
                                    : null,
                            message.event().getRunScheduled().getTagsCount() > 0
                                    ? Set.copyOf(message.event().getRunScheduled().getTagsList())
                                    : null));

                    if (message.event().getRunScheduled().hasConcurrencyGroupId()) {
                        nextRunIdByNewConcurrencyGroupId.compute(
                                message.event().getRunScheduled().getConcurrencyGroupId(),
                                (ignored, previous) -> {
                            if (previous == null) {
                                return message.recipientRunId();
                            }

                            return message.recipientRunId().compareTo(previous) < 0
                                    ? message.recipientRunId()
                                    : previous;
                        });
                    }
                }

                newInboxEvents.add(new NewWorkflowRunInboxRow(
                        message.recipientRunId(),
                        toInstant(message.event().getTimestamp()),
                        message.event()));
            }

            // If there are pending sub workflow runs, make sure those are cancelled, too.
            if (workflowRun.status() == WorkflowRunStatus.CANCELLED) {
                for (final UUID subWorkflowRunId : getPendingSubWorkflowRunIds(workflowRun)) {
                    newInboxEvents.add(new NewWorkflowRunInboxRow(
                            subWorkflowRunId,
                            null,
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(Timestamps.now())
                                    .setRunCancelled(RunCancelled.newBuilder()
                                            .setReason("Parent cancelled")
                                            .build())
                                    .build()));
                }
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

            if (workflowRun.status().isTerminal() && workflowRun.concurrencyGroupId().isPresent()) {
                concurrencyGroupsToUpdate.add(workflowRun.concurrencyGroupId().get());
            }
        }

        if (!newJournalEntries.isEmpty()) {
            dao.createRunJournalEntries(newJournalEntries);
        }

        if (!newWorkflowRuns.isEmpty()) {
            // TODO: Call ScheduleWorkflowRuns instead so concurrency groups are updated, too.
            //  Ensure it can participate in this transaction!
            final List<UUID> createdRunIds = dao.createRuns(newWorkflowRuns);
            assert createdRunIds.size() == newWorkflowRuns.size();
        }

        if (!newInboxEvents.isEmpty()) {
            final int createdInboxEvents = dao.createRunInboxEvents(newInboxEvents);
            assert createdInboxEvents == newInboxEvents.size();
        }

        if (!newActivityTasks.isEmpty()) {
            final int createdActivityTasks = dao.createActivityTasks(newActivityTasks);
            assert createdActivityTasks == newActivityTasks.size();
        }

        final int deletedInboxEvents = dao.deleteRunInboxEvents(
                this.instanceId,
                actions.stream()
                        .map(CompleteWorkflowTaskAction::workflowRun)
                        .map(run -> new DeleteInboxEventsCommand(
                                run.workflowRunId(),
                                /* onlyLocked */ !run.status().isTerminal()))
                        .toList());
        assert deletedInboxEvents >= actions.size();

        if (!nextRunIdByNewConcurrencyGroupId.isEmpty()) {
            final List<WorkflowConcurrencyGroupRow> newConcurrencyGroupRows =
                    nextRunIdByNewConcurrencyGroupId.entrySet().stream()
                            .map(entry -> new WorkflowConcurrencyGroupRow(
                                    /* id */ entry.getKey(),
                                    /* nextRunId */ entry.getValue()))
                            .toList();
            dao.maybeCreateConcurrencyGroups(newConcurrencyGroupRows);
        }

        if (!concurrencyGroupsToUpdate.isEmpty()) {
            final Map<String, String> statusByGroupId = dao.updateConcurrencyGroups(concurrencyGroupsToUpdate);
            assert statusByGroupId.size() == concurrencyGroupsToUpdate.size();

            if (LOGGER.isDebugEnabled()) {
                for (final Map.Entry<String, String> entry : statusByGroupId.entrySet()) {
                    LOGGER.debug("Concurrency group {}: {}", entry.getKey(), entry.getValue());
                }
            }
        }
    }

    List<ActivityTask> pollActivityTasks(final String activityName, final int limit, final Duration lockTimeout) {
        return inJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            return dao.pollAndLockActivityTasks(this.instanceId, activityName, lockTimeout, limit).stream()
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

    // TODO: Make this a batch operation.
    private void abandonActivityTask(final WorkflowDao dao, final ActivityTask task) {
        final int unlockedTasks = dao.unlockActivityTasks(this.instanceId,
                Stream.of(task)
                        .map(t -> new ActivityTaskId(t.workflowRunId(), t.scheduledEventId()))
                        .toList());
        assert unlockedTasks == 1;
    }

    CompletableFuture<Void> completeActivityTask(
            final ActivityTask task, final WorkflowPayload result) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new CompleteActivityTaskAction(task, result, Instant.now()));
    }

    CompletableFuture<Void> failActivityTask(
            final ActivityTask task, final Throwable exception) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new FailActivityTaskAction(task, exception, Instant.now()));
    }

    private void completeActivityTasksInternal(
            final WorkflowDao dao,
            final Collection<CompleteActivityTaskAction> actions) {
        final var tasksToDelete = new ArrayList<ActivityTaskId>(actions.size());
        final var inboxEventsToCreate = new ArrayList<NewWorkflowRunInboxRow>(actions.size());

        for (final CompleteActivityTaskAction action : actions) {
            tasksToDelete.add(new ActivityTaskId(action.task().workflowRunId(), action.task().scheduledEventId()));

            final var taskCompletedBuilder = ActivityTaskCompleted.newBuilder()
                    .setTaskScheduledEventId(action.task().scheduledEventId());
            if (action.result() != null) {
                taskCompletedBuilder.setResult(action.result());
            }
            inboxEventsToCreate.add(new NewWorkflowRunInboxRow(
                    action.task().workflowRunId(),
                    null,
                    WorkflowEvent.newBuilder()
                            .setId(-1)
                            .setTimestamp(toTimestamp(action.timestamp()))
                            .setActivityTaskCompleted(taskCompletedBuilder.build())
                            .build()));
        }

        final int deletedTasks = dao.deleteLockedActivityTasks(this.instanceId, tasksToDelete);
        assert deletedTasks == tasksToDelete.size();

        final int createdInboxEvents = dao.createRunInboxEvents(inboxEventsToCreate);
        assert createdInboxEvents == inboxEventsToCreate.size();
    }

    private void failActivityTasksInternal(final WorkflowDao dao, final Collection<FailActivityTaskAction> actions) {
        final var tasksToDelete = new ArrayList<ActivityTaskId>(actions.size());
        final var inboxEventsToCreate = new ArrayList<NewWorkflowRunInboxRow>(actions.size());

        for (final FailActivityTaskAction action : actions) {
            tasksToDelete.add(new ActivityTaskId(action.task().workflowRunId(), action.task().scheduledEventId()));

            inboxEventsToCreate.add(new NewWorkflowRunInboxRow(
                    action.task().workflowRunId(),
                    null,
                    WorkflowEvent.newBuilder()
                            .setId(-1)
                            .setTimestamp(toTimestamp(action.timestamp()))
                            .setActivityTaskFailed(ActivityTaskFailed.newBuilder()
                                    .setTaskScheduledEventId(action.task().scheduledEventId())
                                    .setFailureDetails(ExceptionUtils.getMessage(action.exception()))
                                    .build())
                            .build()));
        }

        final int deletedTasks = dao.deleteLockedActivityTasks(this.instanceId, tasksToDelete);
        assert deletedTasks == tasksToDelete.size();

        final int createdInboxEvents = dao.createRunInboxEvents(inboxEventsToCreate);
        assert createdInboxEvents == inboxEventsToCreate.size();
    }

    Instant heartbeatActivityTask(final ActivityTaskId taskId, final Duration lockTimeout) {
        final Instant newLockTimeout = inJdbiTransaction(
                handle -> new WorkflowDao(handle).extendActivityTaskLock(
                        this.instanceId, taskId, lockTimeout));
        assert newLockTimeout != null;
        return newLockTimeout;
    }

    private void processTaskActions(final List<TaskAction> actions) {
        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            // TODO: Group by action and process them using batch queries.
            final var completeActivityTaskActions = new ArrayList<CompleteActivityTaskAction>();
            final var failActivityTaskActions = new ArrayList<FailActivityTaskAction>();
            final var completeWorkflowTaskActions = new ArrayList<CompleteWorkflowTaskAction>();

            for (final TaskAction action : actions) {
                switch (action) {
                    case AbandonActivityTaskAction a -> abandonActivityTask(dao, a.task());
                    case CompleteActivityTaskAction c -> completeActivityTaskActions.add(c);
                    case FailActivityTaskAction f -> failActivityTaskActions.add(f);
                    case AbandonWorkflowTaskAction a -> abandonWorkflowTask(dao, a.task());
                    case CompleteWorkflowTaskAction c -> completeWorkflowTaskActions.add(c);
                }
            }

            if (!completeActivityTaskActions.isEmpty()) {
                completeActivityTasksInternal(dao, completeActivityTaskActions);
            }
            if (!failActivityTaskActions.isEmpty()) {
                failActivityTasksInternal(dao, failActivityTaskActions);
            }
            if (!completeWorkflowTaskActions.isEmpty()) {
                completeWorkflowTasksInternal(dao, completeWorkflowTaskActions);
            }
        });
    }

    // TODO: This should not return an internal persistence model.
    WorkflowRunRow getRun(final UUID runId) {
        return withJdbiHandle(handle -> new WorkflowDao(handle).getRun(runId));
    }

    List<WorkflowEvent> getRunJournal(final UUID runId) {
        return withJdbiHandle(handle -> new WorkflowDao(handle).getRunJournal(runId));
    }

    private Set<UUID> getPendingSubWorkflowRunIds(final WorkflowRun run) {
        final var runIdByEventId = new HashMap<Integer, UUID>();

        Stream.concat(run.journal().stream(), run.inbox().stream()).forEach(event -> {
            switch (event.getSubjectCase()) {
                case SUB_WORKFLOW_RUN_SCHEDULED -> {
                    final String runId = event.getSubWorkflowRunScheduled().getRunId();
                    runIdByEventId.put(event.getId(), UUID.fromString(runId));
                }
                case SUB_WORKFLOW_RUN_COMPLETED -> {
                    final int scheduledEventId = event.getSubWorkflowRunCompleted().getRunScheduledEventId();
                    runIdByEventId.remove(scheduledEventId);
                }
                case SUB_WORKFLOW_RUN_FAILED -> {
                    final int scheduledEventId = event.getSubWorkflowRunFailed().getRunScheduledEventId();
                    runIdByEventId.remove(scheduledEventId);
                }
            }
        });

        return Set.copyOf(runIdByEventId.values());
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

    static UUID randomUUIDv7() {
        // UUIDv7 cause BTREE indexes (i.e., primary keys) to bloat less than other UUID versions,
        // because they're time-sortable.
        // https://antonz.org/uuidv7/
        // https://maciejwalkowiak.com/blog/postgres-uuid-primary-key/
        return timeBasedEpochRandomGenerator().generate();
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
