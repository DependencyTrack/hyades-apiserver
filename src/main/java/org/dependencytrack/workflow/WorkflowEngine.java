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

import alpine.event.framework.LoggableUncaughtExceptionHandler;
import alpine.persistence.OrderDirection;
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
import org.dependencytrack.workflow.persistence.mapping.PolledActivityTaskRowMapper;
import org.dependencytrack.workflow.persistence.mapping.PolledWorkflowEventRowMapper;
import org.dependencytrack.workflow.persistence.mapping.PolledWorkflowRunRowMapper;
import org.dependencytrack.workflow.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.workflow.persistence.mapping.WorkflowEventArgumentFactory;
import org.dependencytrack.workflow.persistence.mapping.WorkflowEventSqlArrayType;
import org.dependencytrack.workflow.persistence.mapping.WorkflowPayloadSqlArrayType;
import org.dependencytrack.workflow.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.persistence.model.DeleteInboxEventsCommand;
import org.dependencytrack.workflow.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunInboxRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunJournalRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.PolledActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowEventRow;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowConcurrencyGroupRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunListRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRowUpdate;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.postgres.PostgresPlugin;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static java.util.Objects.requireNonNull;

// TODO: Add metrics for:
//   - Workflow runs scheduled
//   - Workflow runs completed/failed
//   - Activities scheduled
//   - Activities completed/failed
// TODO: Buffer schedule commands for ~5ms.
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

    private final WorkflowEngineConfig config;
    private final Jdbi jdbi;
    private final ReentrantLock stateLock = new ReentrantLock();
    private State state = State.CREATED;
    private ExecutorService taskDispatcherExecutor;
    private Map<String, ExecutorService> executorServiceByName;
    private Buffer<NewExternalEvent> externalEventBuffer;
    private Buffer<TaskAction> taskActionBuffer;

    public WorkflowEngine(final WorkflowEngineConfig config) {
        this.config = requireNonNull(config);
        this.jdbi = Jdbi
                .create(config.dataSource())
                .installPlugin(new PostgresPlugin())
                // Ensure all required mappings are registered *once*
                // on startup. Defining these on a per-query basis imposes
                // additional overhead that is worth avoiding given how
                // frequently queries are being executed.
                // TODO: Don't do this in the engine's constructor.
                .registerArgument(new WorkflowEventArgumentFactory())
                .registerArrayType(Instant.class, "timestamptz")
                .registerArrayType(WorkflowRunStatus.class, "workflow_run_status")
                .registerArrayType(new WorkflowEventSqlArrayType())
                .registerArrayType(new WorkflowPayloadSqlArrayType())
                .registerColumnMapper(
                        WorkflowEvent.class,
                        new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .registerRowMapper(
                        WorkflowRunCountByNameAndStatusRow.class,
                        ConstructorMapper.of(WorkflowRunCountByNameAndStatusRow.class))
                .registerRowMapper(
                        WorkflowRunListRow.class,
                        ConstructorMapper.of(WorkflowRunListRow.class))
                .registerRowMapper(
                        WorkflowRunRow.class,
                        ConstructorMapper.of(WorkflowRunRow.class))
                .registerRowMapper(
                        PolledActivityTaskRow.class,
                        new PolledActivityTaskRowMapper())
                .registerRowMapper(
                        PolledWorkflowEventRow.class,
                        new PolledWorkflowEventRowMapper())
                .registerRowMapper(
                        PolledWorkflowRunRow.class,
                        new PolledWorkflowRunRowMapper());
    }

    public void start() {
        setState(State.STARTING);
        LOGGER.debug("Starting");

        externalEventBuffer = new Buffer<>(
                "workflow-external-event",
                this::flushExternalEvents,
                config.externalEventBuffer().flushInterval(),
                config.externalEventBuffer().maxBatchSize(),
                config.meterRegistry());
        externalEventBuffer.start();

        // The buffer's flush interval should be long enough to allow
        // for more than one task result to be included, but short enough
        // to not block task execution unnecessarily. In a worst-case scenario,
        // task workers can be blocked for an entire flush interval.
        // TODO: Separate buffer for workflow actions from buffer for activity actions?
        //  Workflow tasks usually complete a lot faster than activity tasks.
        taskActionBuffer = new Buffer<>(
                "workflow-task-action",
                this::processTaskActions,
                config.taskActionBuffer().flushInterval(),
                config.taskActionBuffer().maxBatchSize(),
                config.meterRegistry());
        taskActionBuffer.start();

        executorServiceByName = new HashMap<>();

        taskDispatcherExecutor = Executors.newThreadPerTaskExecutor(
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-TaskDispatcher-%d")
                        .build());
        if (config.meterRegistry() != null) {
            new ExecutorServiceMetrics(taskDispatcherExecutor, "WorkflowEngine-TaskDispatcher", null)
                    .bindTo(config.meterRegistry());
        }

        setState(State.RUNNING);
        LOGGER.debug("Started");
    }

    @Override
    public void close() throws IOException {
        setState(State.STOPPING);
        LOGGER.debug("Stopping");

        LOGGER.debug("Waiting for task dispatcher to stop");
        taskDispatcherExecutor.close();
        taskDispatcherExecutor = null;

        LOGGER.debug("Waiting for task executors to stop");
        executorServiceByName.values().forEach(ExecutorService::close);
        executorServiceByName = null;

        LOGGER.debug("Waiting for external event buffer to stop");
        externalEventBuffer.close();
        externalEventBuffer = null;

        LOGGER.debug("Waiting for task action buffer to stop");
        taskActionBuffer.close();
        taskActionBuffer = null;

        setState(State.STOPPED);
        LOGGER.debug("Stopped");
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

        // TODO: Micrometer currently can't instrument this executor type.
        //  Can an update of Micrometer resolve that?
        final ExecutorService executorService = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .name("WorkflowEngine-WorkflowRunner-" + workflowName + "-", 0)
                        .factory());
        if (config.meterRegistry() != null) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-WorkflowRunner-" + workflowName, null)
                    .bindTo(config.meterRegistry());
        }
        executorServiceByName.put(executorName, executorService);

        final var taskProcessor = new WorkflowTaskProcessor<>(
                this, workflowName, workflowRunner, argumentConverter, resultConverter, taskLockTimeout);

        final var taskDispatcher = new TaskDispatcher<>(
                this,
                executorService,
                taskProcessor,
                maxConcurrency,
                config.workflowTaskDispatcher().minPollInterval(),
                config.workflowTaskDispatcher().pollBackoffIntervalFunction(),
                config.meterRegistry());

        taskDispatcherExecutor.execute(taskDispatcher);
    }

    public <A, R> void registerActivityRunner(
            final ActivityRunner<A, R> activityRunner,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration taskLockTimeout) {
        requireNonNull(activityRunner, "activityRunner must not be null");

        // TODO: Find a better way to do this.
        //  It's only temporary to make testing easier.
        final Class<? extends ActivityRunner> activityRunnerClass;
        if (activityRunner instanceof final FaultInjectingActivityRunner<A, R> runner) {
            activityRunnerClass = runner.delegate().getClass();
        } else {
            activityRunnerClass = activityRunner.getClass();
        }

        final var activityAnnotation = activityRunnerClass.getAnnotation(Activity.class);
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

        // TODO: Micrometer currently can't instrument this executor type.
        //  Can an update of Micrometer resolve that?
        final ExecutorService executorService = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .name("WorkflowEngine-ActivityRunner-" + activityName + "-", 0)
                        .factory());
        if (config.meterRegistry() != null) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-ActivityRunner-" + activityName, null)
                    .bindTo(config.meterRegistry());
        }
        executorServiceByName.put(executorName, executorService);

        final var taskProcessor = new ActivityTaskProcessor<>(
                this, activityName, activityRunner, argumentConverter, resultConverter, taskLockTimeout);

        final var taskDispatcher = new TaskDispatcher<>(
                this,
                executorService,
                taskProcessor,
                maxConcurrency,
                config.activityTaskDispatcher().minPollInterval(),
                config.activityTaskDispatcher().pollBackoffIntervalFunction(),
                config.meterRegistry());

        taskDispatcherExecutor.execute(taskDispatcher);
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
                    /* parentId */ null,
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

        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final List<UUID> createdRunIds = dao.createRuns(newWorkflowRunRows);
            assert createdRunIds.size() == newWorkflowRunRows.size()
                    : "Created runs: actual=%d, expected=%d".formatted(
                    createdRunIds.size(), newWorkflowRunRows.size());

            final int createdInboxEvents = dao.createRunInboxEvents(newInboxEventRows);
            assert createdInboxEvents == newInboxEventRows.size()
                    : "Created inbox events: actual=%d, expected=%d".formatted(
                    createdInboxEvents, newInboxEventRows.size());

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

        jdbi.useTransaction(handle -> {
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

        jdbi.useTransaction(handle -> {
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

        jdbi.useTransaction(handle -> {
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
        jdbi.useTransaction(handle -> {
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
        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final Map<UUID, PolledWorkflowRunRow> polledRunById =
                    dao.pollAndLockRuns(this.config.instanceId(), workflowName, taskLockTimeout, limit);
            if (polledRunById.isEmpty()) {
                return Collections.emptyList();
            }

            final Map<UUID, PolledWorkflowEvents> polledEventsByRunId =
                    dao.pollRunEvents(this.config.instanceId(), polledRunById.keySet());

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

        final int unlockedEvents = dao.unlockRunInboxEvents(this.config.instanceId(), task.workflowRunId(), abandonDelay);
        assert unlockedEvents == task.inbox().size();

        final int unlockedWorkflowRuns = dao.unlockRun(this.config.instanceId(), task.workflowRunId());
        assert unlockedWorkflowRuns == 1;
    }

    CompletableFuture<Void> completeWorkflowTask(
            final WorkflowRun workflowRun) throws InterruptedException, TimeoutException {
        return taskActionBuffer.add(new CompleteWorkflowTaskAction(workflowRun));
    }

    private void completeWorkflowTasksInternal(
            final WorkflowDao dao,
            final Collection<CompleteWorkflowTaskAction> actions) {
        final List<WorkflowRun> actionableRuns = actions.stream()
                .map(CompleteWorkflowTaskAction::workflowRun)
                .collect(Collectors.toList());

        final List<UUID> updatedRunIds = dao.updateRuns(
                this.config.instanceId(),
                actionableRuns.stream()
                        .map(run -> new WorkflowRunRowUpdate(
                                run.id(),
                                run.status(),
                                run.customStatus().orElse(null),
                                run.createdAt().orElse(null),
                                run.updatedAt().orElse(null),
                                run.startedAt().orElse(null),
                                run.completedAt().orElse(null)))
                        .toList());

        if (updatedRunIds.size() != actions.size()) {
            final Set<UUID> notUpdatedRunIds = actions.stream()
                    .map(CompleteWorkflowTaskAction::workflowRun)
                    .map(WorkflowRun::id)
                    .filter(runId -> !updatedRunIds.contains(runId))
                    .collect(Collectors.toSet());
            LOGGER.warn("{}/{} workflow runs were not updated, indicating modification by another worker instance: {}",
                    notUpdatedRunIds.size(), actions.size(), notUpdatedRunIds);

            // Since we lost the lock on these runs, we can't act upon them anymore.
            // Note that this is expected behavior and not necessarily reason for concern.
            actionableRuns.removeIf(run -> notUpdatedRunIds.contains(run.id()));
        }

        final var newJournalEntries = new ArrayList<NewWorkflowRunJournalRow>(actions.size() * 2);
        final var newInboxEvents = new ArrayList<NewWorkflowRunInboxRow>(actions.size() * 2);
        final var newWorkflowRuns = new ArrayList<NewWorkflowRunRow>();
        final var newActivityTasks = new ArrayList<NewActivityTaskRow>();
        final var nextRunIdByNewConcurrencyGroupId = new HashMap<String, UUID>();
        final var concurrencyGroupsToUpdate = new HashSet<String>();

        for (final WorkflowRun run : actionableRuns) {
            int sequenceNumber = run.journal().size();
            for (final WorkflowEvent newEvent : run.inbox()) {
                newJournalEntries.add(new NewWorkflowRunJournalRow(
                        run.id(),
                        sequenceNumber++,
                        newEvent));
            }

            for (final WorkflowEvent newEvent : run.pendingTimerElapsedEvents()) {
                newInboxEvents.add(new NewWorkflowRunInboxRow(
                        run.id(),
                        toInstant(newEvent.getTimerElapsed().getElapseAt()),
                        newEvent));
            }

            for (final WorkflowRunMessage message : run.pendingWorkflowMessages()) {
                // If the outbound message is a RunScheduled event, the recipient
                // workflow run will need to be created first.
                if (message.event().hasRunScheduled()) {
                    newWorkflowRuns.add(new NewWorkflowRunRow(
                            message.recipientRunId(),
                            /* parentId */ run.id(),
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
            if (run.status() == WorkflowRunStatus.CANCELLED) {
                for (final UUID subWorkflowRunId : getPendingSubWorkflowRunIds(run)) {
                    newInboxEvents.add(new NewWorkflowRunInboxRow(
                            subWorkflowRunId,
                            /* visibleFrom */ null,
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(Timestamps.now())
                                    .setRunCancelled(RunCancelled.newBuilder()
                                            .setReason("Parent cancelled")
                                            .build())
                                    .build()));
                }
            }

            for (final WorkflowEvent newEvent : run.pendingActivityTaskScheduledEvents()) {
                newActivityTasks.add(new NewActivityTaskRow(
                        run.id(),
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

            if (run.status().isTerminal() && run.concurrencyGroupId().isPresent()) {
                concurrencyGroupsToUpdate.add(run.concurrencyGroupId().get());
            }
        }

        if (!newJournalEntries.isEmpty()) {
            final int journalEntriesCreated = dao.createRunJournalEntries(newJournalEntries);
            assert journalEntriesCreated == newJournalEntries.size()
                    : "Created journal entries: actual=%d, expected=%d".formatted(
                    journalEntriesCreated, newJournalEntries.size());
        }

        if (!newWorkflowRuns.isEmpty()) {
            // TODO: Call ScheduleWorkflowRuns instead so concurrency groups are updated, too.
            //  Ensure it can participate in this transaction!
            final List<UUID> createdRunIds = dao.createRuns(newWorkflowRuns);
            assert createdRunIds.size() == newWorkflowRuns.size()
                    : "Created runs: actual=%d, expected=%d".formatted(
                    createdRunIds.size(), newWorkflowRuns.size());
        }

        if (!newInboxEvents.isEmpty()) {
            final int createdInboxEvents = dao.createRunInboxEvents(newInboxEvents);
            assert createdInboxEvents == newInboxEvents.size()
                    : "Created inbox events: actual=%d, expected=%d".formatted(
                    createdInboxEvents, newInboxEvents.size());
        }

        if (!newActivityTasks.isEmpty()) {
            final int createdActivityTasks = dao.createActivityTasks(newActivityTasks);
            assert createdActivityTasks == newActivityTasks.size()
                    : "Created activity tasks: actual=%d, expected=%d".formatted(
                    createdActivityTasks, newActivityTasks.size());
        }

        final int deletedInboxEvents = dao.deleteRunInboxEvents(
                this.config.instanceId(),
                actionableRuns.stream()
                        .map(run -> new DeleteInboxEventsCommand(
                                run.id(),
                                /* onlyLocked */ !run.status().isTerminal()))
                        .toList());
        assert deletedInboxEvents >= updatedRunIds.size()
                : "Deleted inbox events: actual=%d, expectedAtLeast=%d".formatted(
                deletedInboxEvents, updatedRunIds.size());

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
            assert statusByGroupId.size() == concurrencyGroupsToUpdate.size()
                    : "Updated concurrency groups: actual=%d, expected=%d".formatted(
                    statusByGroupId.size(), concurrencyGroupsToUpdate.size());

            if (LOGGER.isDebugEnabled()) {
                for (final Map.Entry<String, String> entry : statusByGroupId.entrySet()) {
                    LOGGER.debug("Concurrency group {}: {}", entry.getKey(), entry.getValue());
                }
            }
        }
    }

    List<ActivityTask> pollActivityTasks(final String activityName, final int limit, final Duration lockTimeout) {
        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            return dao.pollAndLockActivityTasks(this.config.instanceId(), activityName, lockTimeout, limit).stream()
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
        final int unlockedTasks = dao.unlockActivityTasks(this.config.instanceId(),
                Stream.of(task)
                        .map(t -> new ActivityTaskId(t.workflowRunId(), t.scheduledEventId()))
                        .toList());
        assert unlockedTasks == 1
                : "Abandoned tasks: actual=%d, expected=%d".formatted(unlockedTasks, 1);
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

        final int deletedTasks = dao.deleteLockedActivityTasks(this.config.instanceId(), tasksToDelete);
        assert deletedTasks == tasksToDelete.size()
                : "Deleted activity tasks: actual=%d, expected=%d".formatted(
                deletedTasks, tasksToDelete.size());

        final int createdInboxEvents = dao.createRunInboxEvents(inboxEventsToCreate);
        assert createdInboxEvents == inboxEventsToCreate.size()
                : "Created inbox events: actual=%d, expected=%d".formatted(
                createdInboxEvents, inboxEventsToCreate.size());
    }

    private void failActivityTasksInternal(final WorkflowDao dao, final Collection<FailActivityTaskAction> actions) {
        final var tasksToDelete = new ArrayList<ActivityTaskId>(actions.size());
        final var inboxEventsToCreate = new ArrayList<NewWorkflowRunInboxRow>(actions.size());

        for (final FailActivityTaskAction action : actions) {
            tasksToDelete.add(new ActivityTaskId(action.task().workflowRunId(), action.task().scheduledEventId()));

            inboxEventsToCreate.add(new NewWorkflowRunInboxRow(
                    action.task().workflowRunId(),
                    /* visibleFrom */ null,
                    WorkflowEvent.newBuilder()
                            .setId(-1)
                            .setTimestamp(toTimestamp(action.timestamp()))
                            .setActivityTaskFailed(ActivityTaskFailed.newBuilder()
                                    .setTaskScheduledEventId(action.task().scheduledEventId())
                                    .setFailureDetails(ExceptionUtils.getMessage(action.exception()))
                                    .build())
                            .build()));
        }

        final int deletedTasks = dao.deleteLockedActivityTasks(this.config.instanceId(), tasksToDelete);
        assert deletedTasks == tasksToDelete.size()
                : "Deleted activity tasks: actual=%d, expected=%d".formatted(
                deletedTasks, tasksToDelete.size());

        final int createdInboxEvents = dao.createRunInboxEvents(inboxEventsToCreate);
        assert createdInboxEvents == inboxEventsToCreate.size()
                : "Created inbox events: actual=%d, expected=%d".formatted(
                createdInboxEvents, inboxEventsToCreate.size());
    }

    Instant heartbeatActivityTask(final ActivityTaskId taskId, final Duration lockTimeout) {
        final Instant newLockTimeout = jdbi.inTransaction(
                handle -> new WorkflowDao(handle).extendActivityTaskLock(
                        this.config.instanceId(), taskId, lockTimeout));
        assert newLockTimeout != null;
        return newLockTimeout;
    }

    private void processTaskActions(final List<TaskAction> actions) {
        jdbi.useTransaction(handle -> {
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
    public WorkflowRunRow getRun(final UUID runId) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRun(runId));
    }

    public boolean existsRunWithNonTerminalStatus(final UUID runId) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).existsRunWithNonTerminalStatus(runId));
    }

    // TODO: This should not return an internal persistence model.
    public List<WorkflowRunListRow> getRunListPage(
            final String workflowNameFilter,
            final WorkflowRunStatus statusFilter,
            final String concurrencyGroupIdFilter,
            final Set<String> tagsFilter,
            final String orderBy,
            final OrderDirection orderDirection,
            final int offset,
            final int limit) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunListPage(
                workflowNameFilter, statusFilter, concurrencyGroupIdFilter, tagsFilter, orderBy, orderDirection, offset, limit));
    }

    public List<WorkflowEvent> getRunJournal(final UUID runId) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunJournal(runId));
    }

    public List<WorkflowEvent> getRunInbox(final UUID runId) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunInbox(runId));
    }

    public List<WorkflowRunCountByNameAndStatusRow> getRunStats() {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunCountByNameAndStatus());
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
