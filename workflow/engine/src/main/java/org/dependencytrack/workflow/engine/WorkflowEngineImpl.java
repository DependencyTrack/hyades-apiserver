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
package org.dependencytrack.workflow.engine;

import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.dependencytrack.proto.workflow.api.v1.ActivityTaskCompleted;
import org.dependencytrack.proto.workflow.api.v1.ActivityTaskFailed;
import org.dependencytrack.proto.workflow.api.v1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.api.v1.RunCanceled;
import org.dependencytrack.proto.workflow.api.v1.RunResumed;
import org.dependencytrack.proto.workflow.api.v1.RunScheduled;
import org.dependencytrack.proto.workflow.api.v1.RunSuspended;
import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.dependencytrack.support.liquibase.MigrationExecutor;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.engine.MetadataRegistry.WorkflowMetadata;
import org.dependencytrack.workflow.engine.TaskCommand.AbandonActivityTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.AbandonWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.CompleteActivityTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.CompleteWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.FailActivityTaskCommand;
import org.dependencytrack.workflow.engine.api.ActivityGroup;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowGroup;
import org.dependencytrack.workflow.engine.api.WorkflowRun;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.api.WorkflowSchedule;
import org.dependencytrack.workflow.engine.api.event.WorkflowEngineEvent;
import org.dependencytrack.workflow.engine.api.event.WorkflowEngineEventListener;
import org.dependencytrack.workflow.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.workflow.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowScheduleRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowSchedulesRequest;
import org.dependencytrack.workflow.engine.persistence.JdbiFactory;
import org.dependencytrack.workflow.engine.persistence.WorkflowActivityDao;
import org.dependencytrack.workflow.engine.persistence.WorkflowDao;
import org.dependencytrack.workflow.engine.persistence.WorkflowRunDao;
import org.dependencytrack.workflow.engine.persistence.WorkflowScheduleDao;
import org.dependencytrack.workflow.engine.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.engine.persistence.model.CreateActivityTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.CreateWorkflowRunCommand;
import org.dependencytrack.workflow.engine.persistence.model.CreateWorkflowRunHistoryEntryCommand;
import org.dependencytrack.workflow.engine.persistence.model.CreateWorkflowRunInboxEntryCommand;
import org.dependencytrack.workflow.engine.persistence.model.CreateWorkflowScheduleCommand;
import org.dependencytrack.workflow.engine.persistence.model.DeleteInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.model.GetWorkflowRunHistoryRequest;
import org.dependencytrack.workflow.engine.persistence.model.PollActivityTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.PollWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.UnlockWorkflowRunInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.model.UpdateAndUnlockRunCommand;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowConcurrencyGroupRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.engine.support.Buffer;
import org.dependencytrack.workflow.engine.support.DefaultThreadFactory;
import org.dependencytrack.workflow.engine.support.LoggingUncaughtExceptionHandler;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static java.util.Objects.requireNonNull;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toTimestamp;

// TODO: Add metrics for:
//   - Workflow runs scheduled
//   - Workflow runs completed/failed
//   - Activities scheduled
//   - Activities completed/failed
// TODO: Buffer schedule commands for ~5ms.
final class WorkflowEngineImpl implements WorkflowEngine {

    public enum Status {

        CREATED(1, 3), // 0
        STARTING(2),   // 1
        RUNNING(3),    // 2
        STOPPING(4),   // 3
        STOPPED(1);    // 4

        private final Set<Integer> allowedTransitions;

        Status(final Integer... allowedTransitions) {
            this.allowedTransitions = Set.of(allowedTransitions);
        }

        private boolean canTransitionTo(final Status newStatus) {
            return allowedTransitions.contains(newStatus.ordinal());
        }

        boolean isStoppingOrStopped() {
            return equals(STOPPING) || equals(STOPPED);
        }

        boolean isNotStoppingOrStopped() {
            return !isStoppingOrStopped();
        }

    }

    private record CachedWorkflowRunHistory(List<WorkflowEvent> events, int maxSequenceNumber) {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineImpl.class);

    private final WorkflowEngineConfig config;
    private final Jdbi jdbi;
    private final ReentrantLock statusLock = new ReentrantLock();
    private final MetadataRegistry metadataRegistry = new MetadataRegistry();
    private final Set<WorkflowGroup> workflowGroups = new HashSet<>();
    private final Set<ActivityGroup> activityGroups = new HashSet<>();
    private final List<WorkflowRunsCompletedEventListener> runsCompletedEventListeners = new ArrayList<>();
    private Status status = Status.CREATED;
    @Nullable private ExecutorService taskDispatcherExecutor;
    @Nullable private Map<String, ExecutorService> executorServiceByName;
    @Nullable private ScheduledExecutorService schedulerExecutor;
    @Nullable private ScheduledExecutorService retentionExecutor;
    @Nullable private ExecutorService eventListenerExecutor;
    @Nullable private Buffer<NewExternalEvent> externalEventBuffer;
    @Nullable private Buffer<TaskCommand> taskCommandBuffer;
    @Nullable private Cache<UUID, CachedWorkflowRunHistory> cachedHistoryByRunId;

    WorkflowEngineImpl(final WorkflowEngineConfig config) {
        this.config = requireNonNull(config);
        this.jdbi = JdbiFactory.create(config.dataSource());
    }

    @Override
    public void migrateDatabase() throws Exception {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);

        new MigrationExecutor(
                config.dataSource(),
                "/org/dependencytrack/workflow/engine/persistence/migration/changelog.xml")
                .withChangeLogTableName("workflow_engine_database_changelog")
                .withChangeLogLockTableName("workflow_engine_database_changelog_lock")
                .executeMigration();
    }

    @Override
    public void start() {
        setStatus(Status.STARTING);
        LOGGER.debug("Starting");

        LOGGER.debug("Initializing history cache");
        final var runHistoryCacheBuilder = Caffeine.newBuilder()
                .maximumSize(config.runHistoryCache().maxSize());
        if (config.runHistoryCache().evictAfterAccess() != null) {
            runHistoryCacheBuilder.expireAfterAccess(config.runHistoryCache().evictAfterAccess());
        }
        if (config.meterRegistry() != null) {
            runHistoryCacheBuilder.recordStats();
        }
        cachedHistoryByRunId = runHistoryCacheBuilder.build();
        if (config.meterRegistry() != null) {
            new CaffeineCacheMetrics<>(cachedHistoryByRunId, "WorkflowEngine-RunHistoryCache", null);
        }

        if (!runsCompletedEventListeners.isEmpty()) {
            LOGGER.debug("Starting event listener executor");
            eventListenerExecutor = Executors.newSingleThreadExecutor(
                    new DefaultThreadFactory("WorkflowEngine-EventListener"));
            if (config.meterRegistry() != null) {
                new ExecutorServiceMetrics(eventListenerExecutor, "WorkflowEngine-EventListener", null)
                        .bindTo(config.meterRegistry());
            }
        } else {
            LOGGER.debug("No event listeners registered");
        }

        LOGGER.debug("Starting external event buffer");
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
        // TODO: Separate buffer for workflow commands from buffer for activity commands?
        //  Workflow tasks usually complete a lot faster than activity tasks.
        LOGGER.debug("Starting task command buffer");
        taskCommandBuffer = new Buffer<>(
                "workflow-task-command",
                this::executeTaskCommands,
                config.taskCommandBuffer().flushInterval(),
                config.taskCommandBuffer().maxBatchSize(),
                config.meterRegistry());
        taskCommandBuffer.start();

        executorServiceByName = new HashMap<>();

        taskDispatcherExecutor = Executors.newThreadPerTaskExecutor(
                new DefaultThreadFactory("WorkflowEngine-TaskDispatcher"));
        if (config.meterRegistry() != null) {
            new ExecutorServiceMetrics(taskDispatcherExecutor, "WorkflowEngine-TaskDispatcher", null)
                    .bindTo(config.meterRegistry());
        }

        if (config.scheduler().isEnabled()) {
            LOGGER.debug("Starting scheduler");
            schedulerExecutor = Executors.newSingleThreadScheduledExecutor(
                    new DefaultThreadFactory("WorkflowEngine-Scheduler"));
            if (config.meterRegistry() != null) {
                new ExecutorServiceMetrics(schedulerExecutor, "WorkflowEngine-Scheduler", null)
                        .bindTo(config.meterRegistry());
            }
            schedulerExecutor.scheduleAtFixedRate(
                    new WorkflowScheduler(this, jdbi),
                    config.scheduler().initialDelay().toMillis(),
                    config.scheduler().pollInterval().toMillis(),
                    TimeUnit.MILLISECONDS);
        } else {
            LOGGER.debug("Scheduler is disabled");
        }

        if (config.retention().isWorkerEnabled()) {
            LOGGER.debug("Starting retention worker");
            retentionExecutor = Executors.newSingleThreadScheduledExecutor(
                    new DefaultThreadFactory("WorkflowEngine-RetentionWorker"));
            if (config.meterRegistry() != null) {
                new ExecutorServiceMetrics(retentionExecutor, "WorkflowEngine-RetentionWorker", null)
                        .bindTo(config.meterRegistry());
            }
            retentionExecutor.scheduleAtFixedRate(
                    new WorkflowRetentionWorker(jdbi, config.retention().days()),
                    config.retention().workerInitialDelay().toMillis(),
                    config.retention().workerInterval().toMillis(),
                    TimeUnit.MILLISECONDS);
        } else {
            LOGGER.debug("Retention worker is disabled");
        }

        for (final WorkflowGroup group : workflowGroups) {
            LOGGER.debug("Starting workflow group {}", group.name());
            startWorkflowGroup(group);
        }

        for (final ActivityGroup group : activityGroups) {
            LOGGER.debug("Starting activity group {}", group.name());
            startActivityGroup(group);
        }

        setStatus(Status.RUNNING);
        LOGGER.debug("Started");
    }

    @Override
    public void close() throws IOException {
        setStatus(Status.STOPPING);
        LOGGER.debug("Stopping");

        if (retentionExecutor != null) {
            LOGGER.debug("Waiting for retention worker to stop");
            retentionExecutor.close();
            retentionExecutor = null;
        }

        if (schedulerExecutor != null) {
            LOGGER.debug("Waiting for scheduler to stop");
            schedulerExecutor.close();
            schedulerExecutor = null;
        }

        if (taskDispatcherExecutor != null) {
            LOGGER.debug("Waiting for task dispatcher to stop");
            taskDispatcherExecutor.close();
            taskDispatcherExecutor = null;
        }

        if (executorServiceByName != null) {
            LOGGER.debug("Waiting for task executors to stop");
            executorServiceByName.values().forEach(ExecutorService::close);
            executorServiceByName = null;
        }

        if (externalEventBuffer != null) {
            LOGGER.debug("Waiting for external event buffer to stop");
            externalEventBuffer.close();
            externalEventBuffer = null;
        }

        if (taskCommandBuffer != null) {
            LOGGER.debug("Waiting for task command buffer to stop");
            taskCommandBuffer.close();
            taskCommandBuffer = null;
        }

        if (eventListenerExecutor != null) {
            eventListenerExecutor.close();
            eventListenerExecutor = null;
            runsCompletedEventListeners.clear();
        }

        if (cachedHistoryByRunId != null) {
            cachedHistoryByRunId.invalidateAll();
            cachedHistoryByRunId = null;
        }

        setStatus(Status.STOPPED);
        LOGGER.debug("Stopped");
    }

    @Override
    public <A, R> void register(
            final WorkflowExecutor<A, R> workflowExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.register(workflowExecutor, argumentConverter, resultConverter, lockTimeout);
    }

    <A, R> void registerWorkflowInternal(
            final String workflowName,
            final int workflowVersion,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final WorkflowExecutor<A, R> workflowExecutor) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.register(workflowName, workflowVersion, argumentConverter, resultConverter, lockTimeout, workflowExecutor);
    }

    @Override
    public <A, R> void register(
            final ActivityExecutor<A, R> activityExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.register(activityExecutor, argumentConverter, resultConverter, lockTimeout);
    }

    <A, R> void registerActivityInternal(
            final String activityName,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final boolean heartbeatEnabled,
            final ActivityExecutor<A, R> activityExecutor) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.register(activityName, argumentConverter, resultConverter, lockTimeout, heartbeatEnabled, activityExecutor);
    }

    @Override
    public void mount(final WorkflowGroup group) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        requireNonNull(group, "group must not be null");

        for (final String workflowName : group.workflowNames()) {
            try {
                metadataRegistry.getWorkflowMetadata(workflowName);
            } catch (NoSuchElementException e) {
                throw new IllegalStateException("Workflow %s is not registered".formatted(workflowName), e);
            }
        }

        workflowGroups.add(group);
    }

    @Override
    public void mount(final ActivityGroup group) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        requireNonNull(group, "group must not be null");

        for (final String activityName : group.activityNames()) {
            try {
                metadataRegistry.getActivityMetadata(activityName);
            } catch (NoSuchElementException e) {
                throw new IllegalStateException("Activity %s is not registered".formatted(activityName), e);
            }
        }

        activityGroups.add(group);
    }

    @Override
    public void addEventListener(final WorkflowEngineEventListener<?> listener) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        requireNonNull(listener, "listener must not be null");
        switch (listener) {
            case WorkflowRunsCompletedEventListener it -> runsCompletedEventListeners.add(it);
        }
    }

    @Override
    public List<UUID> createRuns(final Collection<CreateWorkflowRunRequest<?>> options) {
        final var now = Timestamps.now();
        final var createWorkflowRunCommands = new ArrayList<CreateWorkflowRunCommand>(options.size());
        final var createInboxEntryCommand = new ArrayList<CreateWorkflowRunInboxEntryCommand>(options.size());
        final var nextRunIdByConcurrencyGroupId = new HashMap<String, UUID>();

        for (final CreateWorkflowRunRequest<?> option : options) {
            //noinspection rawtypes
            final WorkflowMetadata workflowMetadata =
                    metadataRegistry.getWorkflowMetadata(option.workflowName());

            final UUID runId = timeBasedEpochRandomGenerator().generate();
            createWorkflowRunCommands.add(
                    new CreateWorkflowRunCommand(
                            runId,
                            /* parentId */ null,
                            option.workflowName(),
                            option.workflowVersion(),
                            option.concurrencyGroupId(),
                            option.priority(),
                            option.labels()));

            final var runScheduledBuilder = RunScheduled.newBuilder()
                    .setWorkflowName(option.workflowName())
                    .setWorkflowVersion(option.workflowVersion());
            if (option.concurrencyGroupId() != null) {
                runScheduledBuilder.setConcurrencyGroupId(option.concurrencyGroupId());
            }
            if (option.priority() != null) {
                runScheduledBuilder.setPriority(option.priority());
            }
            if (option.labels() != null) {
                runScheduledBuilder.putAllLabels(option.labels());
            }
            if (option.argument() != null) {
                final WorkflowPayload argumentPayload;
                if (option.argument() instanceof final WorkflowPayload payload) {
                    argumentPayload = payload;
                } else {
                    //noinspection unchecked
                    argumentPayload = workflowMetadata.argumentConverter().convertToPayload(option.argument());
                }
                runScheduledBuilder.setArgument(argumentPayload);
            }

            createInboxEntryCommand.add(
                    new CreateWorkflowRunInboxEntryCommand(
                            runId,
                            null,
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

            final List<UUID> createdRunIds = dao.createRuns(createWorkflowRunCommands);
            assert createdRunIds.size() == createWorkflowRunCommands.size()
                    : "Created runs: actual=%d, expected=%d".formatted(
                    createdRunIds.size(), createWorkflowRunCommands.size());

            final int createdInboxEvents = dao.createRunInboxEvents(createInboxEntryCommand);
            assert createdInboxEvents == createInboxEntryCommand.size()
                    : "Created inbox events: actual=%d, expected=%d".formatted(
                    createdInboxEvents, createInboxEntryCommand.size());

            if (!newConcurrencyGroupRows.isEmpty()) {
                dao.maybeCreateConcurrencyGroups(newConcurrencyGroupRows);
            }

            return createdRunIds;
        });
    }

    @Nullable
    public WorkflowRun getRun(final UUID runId) {
        final WorkflowRunRow runRow = jdbi.withHandle(handle -> new WorkflowDao(handle).getRun(runId));
        if (runRow == null) {
            return null;
        }

        return new WorkflowRun(
                runRow.id(),
                runRow.workflowName(),
                runRow.workflowVersion(),
                runRow.status(),
                runRow.customStatus(),
                runRow.priority(),
                runRow.concurrencyGroupId(),
                runRow.labels(),
                runRow.createdAt(),
                runRow.updatedAt(),
                runRow.startedAt(),
                runRow.completedAt());
    }

    @Override
    public Page<WorkflowRun> listRuns(final ListWorkflowRunsRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).listRuns(request));
    }

    @Override
    public void requestRunCancellation(final UUID runId, final String reason) {
        final var cancellationEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunCanceled(RunCanceled.newBuilder()
                        .setReason(reason)
                        .build())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunRow run = dao.getRun(runId);
            if (run == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (run.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            }

            final boolean hasPendingCancellation = dao.getRunInbox(runId).stream()
                    .anyMatch(WorkflowEvent::hasRunCanceled);
            if (hasPendingCancellation) {
                throw new IllegalStateException("Cancellation of workflow run %s already pending".formatted(runId));
            }

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new CreateWorkflowRunInboxEntryCommand(runId, null, cancellationEvent)));
            assert createdInboxEvents == 1;
        });
    }

    @Override
    public void requestRunSuspension(final UUID runId) {
        final var suspensionEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunSuspended(RunSuspended.getDefaultInstance())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunRow run = dao.getRun(runId);
            if (run == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (run.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            } else if (run.status() == WorkflowRunStatus.SUSPENDED) {
                throw new IllegalStateException("Workflow run %s is already suspended".formatted(runId));
            }

            final boolean hasPendingSuspension = dao.getRunInbox(runId).stream()
                    .anyMatch(WorkflowEvent::hasRunSuspended);
            if (hasPendingSuspension) {
                throw new IllegalStateException("Suspension of workflow run %s is already pending".formatted(runId));
            }

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new CreateWorkflowRunInboxEntryCommand(runId, null, suspensionEvent)));
            assert createdInboxEvents == 1;
        });
    }

    @Override
    public void requestRunResumption(final UUID runId) {
        final var resumeEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunResumed(RunResumed.getDefaultInstance())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunRow run = dao.getRun(runId);
            if (run == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (run.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            } else if (run.status() != WorkflowRunStatus.SUSPENDED) {
                throw new IllegalStateException("Workflow run %s can not be resumed because it is not suspended".formatted(runId));
            }

            final boolean hasPendingResumption = dao.getRunInbox(runId).stream()
                    .anyMatch(WorkflowEvent::hasRunResumed);
            if (hasPendingResumption) {
                throw new IllegalStateException("Resumption of workflow run %s is already pending".formatted(runId));
            }

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new CreateWorkflowRunInboxEntryCommand(runId, null, resumeEvent)));
            assert createdInboxEvents == 1;
        });
    }

    @Override
    public Page<WorkflowEvent> listRunHistory(final ListWorkflowRunHistoryRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).listRunHistory(request));
    }

    @Override
    public CompletableFuture<Void> sendExternalEvent(
            final UUID workflowRunId,
            final String eventId,
            final WorkflowPayload content) {
        requireStatusAnyOf(Status.RUNNING);

        try {
            return externalEventBuffer.add(new NewExternalEvent(workflowRunId, eventId, content));
        } catch (InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<WorkflowSchedule> createSchedules(final Collection<CreateWorkflowScheduleRequest> requests) {
        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowScheduleDao(handle);

            final var now = Instant.now();
            final var createScheduleCommands = new ArrayList<CreateWorkflowScheduleCommand>(requests.size());

            for (final CreateWorkflowScheduleRequest request : requests) {
                final Schedule cronSchedule;
                try {
                    cronSchedule = Schedule.create(request.cron());
                } catch (InvalidExpressionException e) {
                    throw new IllegalArgumentException("Cron expression %s of schedule %s is invalid".formatted(
                            request.cron(), request.name()), e);
                }

                final Instant nextFireAt;
                if (request.initialDelay() == null) {
                    nextFireAt = cronSchedule.next(Date.from(now)).toInstant();
                } else {
                    nextFireAt = now.plus(request.initialDelay());
                }

                createScheduleCommands.add(
                        new CreateWorkflowScheduleCommand(
                                request.name(),
                                request.cron(),
                                request.workflowName(),
                                request.workflowVersion(),
                                request.concurrencyGroupId(),
                                request.priority(),
                                request.labels(),
                                request.argument(),
                                nextFireAt));
            }

            return dao.createSchedules(createScheduleCommands);
        });
    }

    @Override
    public Page<WorkflowSchedule> listSchedules(final ListWorkflowSchedulesRequest request) {
        return jdbi.withHandle(handle -> new WorkflowScheduleDao(handle).listSchedules(request));
    }

    private void startWorkflowGroup(final WorkflowGroup group) {
        requireStatusAnyOf(Status.STARTING);
        requireNonNull(group, "group must not be null");

        final String executorName = "WorkflowEngine-WorkflowGroup-%s".formatted(group.name());
        if (executorServiceByName.containsKey(executorName)) {
            throw new IllegalStateException("Workflow group %s is already registered".formatted(group.name()));
        }

        final ExecutorService executorService = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .uncaughtExceptionHandler(new LoggingUncaughtExceptionHandler())
                        .name(executorName, 0)
                        .factory());
        if (config.meterRegistry() != null) {
            new ExecutorServiceMetrics(executorService, executorName, null)
                    .bindTo(config.meterRegistry());
        }
        executorServiceByName.put(executorName, executorService);

        final var taskDispatcher = new TaskDispatcher<>(
                this,
                executorService,
                new WorkflowTaskManager(this, group, metadataRegistry),
                group.maxConcurrency(),
                config.workflowTaskDispatcher().minPollInterval(),
                config.workflowTaskDispatcher().pollBackoffIntervalFunction(),
                config.meterRegistry());

        taskDispatcherExecutor.execute(taskDispatcher);
    }

    private void startActivityGroup(final ActivityGroup group) {
        requireStatusAnyOf(Status.STARTING);
        requireNonNull(group, "group must not be null");

        final String executorName = "WorkflowEngine-ActivityGroup-%s".formatted(group.name());
        if (executorServiceByName.containsKey(executorName)) {
            throw new IllegalStateException("Activity group %s is already mounted".formatted(group.name()));
        }

        final ExecutorService executorService = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .uncaughtExceptionHandler(new LoggingUncaughtExceptionHandler())
                        .name(executorName, 0)
                        .factory());
        if (config.meterRegistry() != null) {
            new ExecutorServiceMetrics(executorService, executorName, null)
                    .bindTo(config.meterRegistry());
        }
        executorServiceByName.put(executorName, executorService);

        final var taskDispatcher = new TaskDispatcher<>(
                this,
                executorService,
                new ActivityTaskManager(this, group, metadataRegistry),
                group.maxConcurrency(),
                config.activityTaskDispatcher().minPollInterval(),
                config.activityTaskDispatcher().pollBackoffIntervalFunction(),
                config.meterRegistry());

        taskDispatcherExecutor.execute(taskDispatcher);
    }

    private void flushExternalEvents(final List<NewExternalEvent> externalEvents) {
        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final var now = Timestamps.now();
            dao.createRunInboxEvents(externalEvents.stream()
                    .map(externalEvent -> new CreateWorkflowRunInboxEntryCommand(
                            externalEvent.workflowRunId(),
                            null,
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(now)
                                    .setExternalEventReceived(
                                            ExternalEventReceived.newBuilder()
                                                    .setId(externalEvent.eventId())
                                                    .build())
                                    .build()
                    ))
                    .toList());
        });
    }

    List<WorkflowTask> pollWorkflowTasks(final Collection<PollWorkflowTaskCommand> pollCommands, final int limit) {
        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            // TODO: We could introduce stickyness to workflow runs, such that the same run will be processed
            //  by the same worker instance for at least a certain amount of time.
            //  This would makes caches more efficient. Currently each instance collaborating on processing
            //  a given workflow run will maintain its own cache.

            final Map<UUID, PolledWorkflowRunRow> polledRunById =
                    dao.pollAndLockRuns(this.config.instanceId(), pollCommands, limit);
            if (polledRunById.isEmpty()) {
                return Collections.emptyList();
            }

            final var historyRequests = new ArrayList<GetWorkflowRunHistoryRequest>(polledRunById.size());
            final var cachedHistoryByRunId = new HashMap<UUID, List<WorkflowEvent>>(polledRunById.size());
            for (final UUID runId : polledRunById.keySet()) {
                final CachedWorkflowRunHistory cachedHistory = this.cachedHistoryByRunId.getIfPresent(runId);
                if (cachedHistory == null) {
                    historyRequests.add(new GetWorkflowRunHistoryRequest(runId, -1));
                } else {
                    cachedHistoryByRunId.put(runId, cachedHistory.events());
                    historyRequests.add(new GetWorkflowRunHistoryRequest(runId, cachedHistory.maxSequenceNumber()));
                }
            }

            final Map<UUID, PolledWorkflowEvents> polledEventsByRunId =
                    dao.pollRunEvents(this.config.instanceId(), historyRequests);

            return polledRunById.values().stream()
                    .map(polledRun -> {
                        final PolledWorkflowEvents polledEvents = polledEventsByRunId.get(polledRun.id());
                        final List<WorkflowEvent> cachedHistoryEvents = cachedHistoryByRunId.get(polledRun.id());

                        final var history = new ArrayList<WorkflowEvent>(
                                polledEvents.history().size()
                                + (cachedHistoryEvents != null ? cachedHistoryEvents.size() : 0));
                        if (cachedHistoryEvents != null) {
                            history.addAll(cachedHistoryEvents);
                        }
                        history.addAll(polledEvents.history());

                        this.cachedHistoryByRunId.put(polledRun.id(), new CachedWorkflowRunHistory(
                                history, polledEvents.maxHistoryEventSequenceNumber()));

                        return new WorkflowTask(
                                polledRun.id(),
                                polledRun.workflowName(),
                                polledRun.workflowVersion(),
                                polledRun.concurrencyGroupId(),
                                polledRun.priority(),
                                polledRun.labels(),
                                polledEvents.maxInboxEventDequeueCount(),
                                history,
                                polledEvents.inbox());
                    })
                    .toList();
        });
    }

    CompletableFuture<Void> abandonWorkflowTask(
            final WorkflowTask task) throws InterruptedException, TimeoutException {
        return taskCommandBuffer.add(new AbandonWorkflowTaskCommand(task));
    }

    private void abandonWorkflowTasksInternal(
            final WorkflowDao dao,
            final Collection<AbandonWorkflowTaskCommand> abandonCommands) {
        // TODO: Make this configurable on a per-workflow basis.
        final IntervalFunction abandonDelayIntervalFunction =
                IntervalFunction.ofExponentialBackoff(
                        Duration.ofSeconds(5), 1.5, Duration.ofMinutes(30));

        final List<UnlockWorkflowRunInboxEventsCommand> unlockCommands = abandonCommands.stream()
                .map(abandonCommand -> {
                    final Duration visibilityDelay = Duration.ofMillis(
                            abandonDelayIntervalFunction.apply(abandonCommand.task().attempt() + 1));

                    return new UnlockWorkflowRunInboxEventsCommand(abandonCommand.task().workflowRunId(), visibilityDelay);
                })
                .toList();

        final int unlockedEvents = dao.unlockRunInboxEvents(this.config.instanceId(), unlockCommands);
        assert unlockedEvents > 1;

        final int unlockedWorkflowRuns = dao.unlockRuns(
                this.config.instanceId(),
                abandonCommands.stream()
                        .map(abandonCommand -> abandonCommand.task().workflowRunId())
                        .toList());
        assert unlockedWorkflowRuns == abandonCommands.size();
    }

    CompletableFuture<Void> completeWorkflowTask(
            final WorkflowRunState workflowRunState) throws InterruptedException, TimeoutException {
        return taskCommandBuffer.add(new CompleteWorkflowTaskCommand(workflowRunState));
    }

    private void completeWorkflowTasksInternal(
            final WorkflowDao workflowDao,
            final WorkflowActivityDao activityDao,
            final Collection<CompleteWorkflowTaskCommand> commands,
            final Collection<WorkflowEngineEvent> engineEvents) {
        final List<WorkflowRunState> actionableRuns = commands.stream()
                .map(CompleteWorkflowTaskCommand::workflowRunState)
                .collect(Collectors.toList());

        final List<UUID> updatedRunIds = workflowDao.updateAndUnlockRuns(
                this.config.instanceId(),
                actionableRuns.stream()
                        .map(run -> new UpdateAndUnlockRunCommand(
                                run.id(),
                                run.status(),
                                run.customStatus(),
                                run.createdAt(),
                                run.updatedAt(),
                                run.startedAt(),
                                run.completedAt()))
                        .toList());

        if (updatedRunIds.size() != commands.size()) {
            final Set<UUID> notUpdatedRunIds = commands.stream()
                    .map(CompleteWorkflowTaskCommand::workflowRunState)
                    .map(WorkflowRunState::id)
                    .filter(runId -> !updatedRunIds.contains(runId))
                    .collect(Collectors.toSet());
            LOGGER.warn("{}/{} workflow runs were not updated, indicating modification by another worker instance: {}",
                    notUpdatedRunIds.size(), commands.size(), notUpdatedRunIds);

            // Since we lost the lock on these runs, we can't act upon them anymore.
            // Note that this is expected behavior and not necessarily reason for concern.
            actionableRuns.removeIf(run -> notUpdatedRunIds.contains(run.id()));
        }

        final var createHistoryEntryCommands = new ArrayList<CreateWorkflowRunHistoryEntryCommand>(commands.size() * 2);
        final var createInboxEntryCommands = new ArrayList<CreateWorkflowRunInboxEntryCommand>(commands.size() * 2);
        final var createWorkflowRunCommands = new ArrayList<CreateWorkflowRunCommand>();
        final var continuedAsNewRunIds = new ArrayList<UUID>();
        final var createActivityTaskCommands = new ArrayList<CreateActivityTaskCommand>();
        final var nextRunIdByNewConcurrencyGroupId = new HashMap<String, UUID>();
        final var concurrencyGroupsToUpdate = new HashSet<String>();
        final var completedRuns = new ArrayList<WorkflowRun>();

        for (final WorkflowRunState run : actionableRuns) {
            if (!runsCompletedEventListeners.isEmpty() && run.status().isTerminal()) {
                completedRuns.add(new WorkflowRun(
                        run.id(),
                        run.workflowName(),
                        run.workflowVersion(),
                        run.status(),
                        run.customStatus(),
                        run.priority(),
                        run.concurrencyGroupId(),
                        run.labels(),
                        run.createdAt(),
                        run.updatedAt(),
                        run.startedAt(),
                        run.completedAt()));
            }

            int sequenceNumber = run.history().size();
            for (final WorkflowEvent newEvent : run.inbox()) {
                createHistoryEntryCommands.add(
                        new CreateWorkflowRunHistoryEntryCommand(
                                run.id(),
                                sequenceNumber++,
                                newEvent));
            }

            for (final WorkflowEvent newEvent : run.pendingTimerElapsedEvents()) {
                createInboxEntryCommands.add(
                        new CreateWorkflowRunInboxEntryCommand(
                                run.id(),
                                toInstant(newEvent.getTimerElapsed().getElapseAt()),
                                newEvent));
            }

            for (final WorkflowRunMessage message : run.pendingWorkflowMessages()) {
                // If the outbound message is a RunScheduled event, the recipient
                // workflow run will need to be created first.
                boolean shouldCreateWorkflowRun = message.event().hasRunScheduled();

                // If this is the run re-scheduling itself as part of he "continue as new"
                // mechanism, no new run needs to be created.
                shouldCreateWorkflowRun &= !(run.continuedAsNew() && message.recipientRunId().equals(run.id()));

                if (shouldCreateWorkflowRun) {
                    createWorkflowRunCommands.add(
                            new CreateWorkflowRunCommand(
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
                                    message.event().getRunScheduled().getLabelsCount() > 0
                                            ? Map.copyOf(message.event().getRunScheduled().getLabelsMap())
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

                createInboxEntryCommands.add(
                        new CreateWorkflowRunInboxEntryCommand(
                                message.recipientRunId(),
                                toInstant(message.event().getTimestamp()),
                                message.event()));
            }

            // If there are pending sub workflow runs, make sure those are canceled, too.
            if (run.status() == WorkflowRunStatus.CANCELED) {
                for (final UUID subWorkflowRunId : getPendingSubWorkflowRunIds(run)) {
                    createInboxEntryCommands.add(
                            new CreateWorkflowRunInboxEntryCommand(
                                    subWorkflowRunId,
                                    /* visibleFrom */ null,
                                    WorkflowEvent.newBuilder()
                                            .setId(-1)
                                            .setTimestamp(Timestamps.now())
                                            .setRunCanceled(RunCanceled.newBuilder()
                                                    .setReason("Parent canceled")
                                                    .build())
                                            .build()));
                }
            }

            for (final WorkflowEvent newEvent : run.pendingActivityTaskScheduledEvents()) {
                createActivityTaskCommands.add(
                        new CreateActivityTaskCommand(
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

            if (run.continuedAsNew()) {
                continuedAsNewRunIds.add(run.id());
            }

            if (run.status().isTerminal() && run.concurrencyGroupId() != null) {
                concurrencyGroupsToUpdate.add(run.concurrencyGroupId());
            }
        }

        if (!continuedAsNewRunIds.isEmpty()) {
            workflowDao.truncateRunHistories(continuedAsNewRunIds);
        }

        if (!createHistoryEntryCommands.isEmpty()) {
            final int historyEntriesCreated = workflowDao.createRunHistoryEntries(createHistoryEntryCommands);
            assert historyEntriesCreated == createHistoryEntryCommands.size()
                    : "Created history entries: actual=%d, expected=%d".formatted(
                    historyEntriesCreated, createHistoryEntryCommands.size());
        }

        if (!createWorkflowRunCommands.isEmpty()) {
            // TODO: Call ScheduleWorkflowRuns instead so concurrency groups are updated, too.
            //  Ensure it can participate in this transaction!
            final List<UUID> createdRunIds = workflowDao.createRuns(createWorkflowRunCommands);
            assert createdRunIds.size() == createWorkflowRunCommands.size()
                    : "Created runs: actual=%d, expected=%d".formatted(
                    createdRunIds.size(), createWorkflowRunCommands.size());
        }

        if (!createInboxEntryCommands.isEmpty()) {
            final int createdInboxEvents = workflowDao.createRunInboxEvents(createInboxEntryCommands);
            assert createdInboxEvents == createInboxEntryCommands.size()
                    : "Created inbox events: actual=%d, expected=%d".formatted(
                    createdInboxEvents, createInboxEntryCommands.size());
        }

        if (!createActivityTaskCommands.isEmpty()) {
            final int createdActivityTasks = activityDao.createActivityTasks(createActivityTaskCommands);
            assert createdActivityTasks == createActivityTaskCommands.size()
                    : "Created activity tasks: actual=%d, expected=%d".formatted(
                    createdActivityTasks, createActivityTaskCommands.size());
        }

        final int deletedInboxEvents = workflowDao.deleteRunInboxEvents(
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
            workflowDao.maybeCreateConcurrencyGroups(newConcurrencyGroupRows);
        }

        if (!concurrencyGroupsToUpdate.isEmpty()) {
            final Map<String, String> statusByGroupId = workflowDao.updateConcurrencyGroups(concurrencyGroupsToUpdate);
            assert statusByGroupId.size() == concurrencyGroupsToUpdate.size()
                    : "Updated concurrency groups: actual=%d, expected=%d".formatted(
                    statusByGroupId.size(), concurrencyGroupsToUpdate.size());

            if (LOGGER.isDebugEnabled()) {
                for (final Map.Entry<String, String> entry : statusByGroupId.entrySet()) {
                    LOGGER.debug("Concurrency group {}: {}", entry.getKey(), entry.getValue());
                }
            }
        }

        if (!completedRuns.isEmpty()) {
            engineEvents.add(new WorkflowRunsCompletedEvent(completedRuns));
        }
    }

    List<ActivityTask> pollActivityTasks(final Collection<PollActivityTaskCommand> pollCommands, final int limit) {
        return jdbi.inTransaction(handle -> {
            final var activityDao = new WorkflowActivityDao(handle);

            return activityDao.pollAndLockActivityTasks(this.config.instanceId(), pollCommands, limit).stream()
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
        return taskCommandBuffer.add(new AbandonActivityTaskCommand(task));
    }

    private void abandonActivityTasksInternal(
            final WorkflowActivityDao activityDao,
            final Collection<AbandonActivityTaskCommand> commands) {
        final int abandonedTasks = activityDao.unlockActivityTasks(
                this.config.instanceId(),
                commands.stream()
                        .map(command -> new ActivityTaskId(
                                command.task().workflowRunId(),
                                command.task().scheduledEventId()))
                        .toList());
        assert abandonedTasks == commands.size()
                : "Abandoned tasks: actual=%d, expected=%d".formatted(abandonedTasks, 1);
    }

    CompletableFuture<Void> completeActivityTask(
            final ActivityTask task, @Nullable final WorkflowPayload result) throws InterruptedException, TimeoutException {
        return taskCommandBuffer.add(new CompleteActivityTaskCommand(task, result, Instant.now()));
    }

    CompletableFuture<Void> failActivityTask(
            final ActivityTask task, final Throwable exception) throws InterruptedException, TimeoutException {
        return taskCommandBuffer.add(new FailActivityTaskCommand(task, exception, Instant.now()));
    }

    private void completeActivityTasksInternal(
            final WorkflowDao workflowDao,
            final WorkflowActivityDao activityDao,
            final Collection<CompleteActivityTaskCommand> commands) {
        final var tasksToDelete = new ArrayList<ActivityTaskId>(commands.size());
        final var inboxEventsToCreate = new ArrayList<CreateWorkflowRunInboxEntryCommand>(commands.size());

        for (final CompleteActivityTaskCommand command : commands) {
            tasksToDelete.add(new ActivityTaskId(command.task().workflowRunId(), command.task().scheduledEventId()));

            final var taskCompletedBuilder = ActivityTaskCompleted.newBuilder()
                    .setTaskScheduledEventId(command.task().scheduledEventId());
            if (command.result() != null) {
                taskCompletedBuilder.setResult(command.result());
            }
            inboxEventsToCreate.add(
                    new CreateWorkflowRunInboxEntryCommand(
                            command.task().workflowRunId(),
                            null,
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(toTimestamp(command.timestamp()))
                                    .setActivityTaskCompleted(taskCompletedBuilder.build())
                                    .build()));
        }

        final int deletedTasks = activityDao.deleteLockedActivityTasks(this.config.instanceId(), tasksToDelete);
        assert deletedTasks == tasksToDelete.size()
                : "Deleted activity tasks: actual=%d, expected=%d".formatted(
                deletedTasks, tasksToDelete.size());

        final int createdInboxEvents = workflowDao.createRunInboxEvents(inboxEventsToCreate);
        assert createdInboxEvents == inboxEventsToCreate.size()
                : "Created inbox events: actual=%d, expected=%d".formatted(
                createdInboxEvents, inboxEventsToCreate.size());
    }

    private void failActivityTasksInternal(
            final WorkflowDao workflowDao,
            final WorkflowActivityDao activityDao,
            final Collection<FailActivityTaskCommand> commands) {
        final var tasksToDelete = new ArrayList<ActivityTaskId>(commands.size());
        final var inboxEventsToCreate = new ArrayList<CreateWorkflowRunInboxEntryCommand>(commands.size());

        for (final FailActivityTaskCommand command : commands) {
            tasksToDelete.add(new ActivityTaskId(command.task().workflowRunId(), command.task().scheduledEventId()));

            inboxEventsToCreate.add(
                    new CreateWorkflowRunInboxEntryCommand(
                            command.task().workflowRunId(),
                            /* visibleFrom */ null,
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(toTimestamp(command.timestamp()))
                                    .setActivityTaskFailed(ActivityTaskFailed.newBuilder()
                                            .setTaskScheduledEventId(command.task().scheduledEventId())
                                            .setFailure(FailureConverter.toFailure(command.exception()))
                                            .build())
                                    .build()));
        }

        final int deletedTasks = activityDao.deleteLockedActivityTasks(this.config.instanceId(), tasksToDelete);
        assert deletedTasks == tasksToDelete.size()
                : "Deleted activity tasks: actual=%d, expected=%d".formatted(
                deletedTasks, tasksToDelete.size());

        final int createdInboxEvents = workflowDao.createRunInboxEvents(inboxEventsToCreate);
        assert createdInboxEvents == inboxEventsToCreate.size()
                : "Created inbox events: actual=%d, expected=%d".formatted(
                createdInboxEvents, inboxEventsToCreate.size());
    }

    Instant heartbeatActivityTask(final ActivityTaskId taskId, final Duration lockTimeout) {
        return jdbi.inTransaction(handle -> {
            final Instant newLockedUntil = new WorkflowActivityDao(handle).extendActivityTaskLock(
                    this.config.instanceId(), taskId, lockTimeout);
            if (newLockedUntil == null) {
                throw new IllegalStateException(
                        "Lock of activity task %s was not extended; Did we lose the lock already?".formatted(taskId));
            }

            return newLockedUntil;
        });
    }

    private void executeTaskCommands(final List<TaskCommand> commands) {
        final var engineEvents = new ArrayList<WorkflowEngineEvent>();

        jdbi.useTransaction(handle -> {
            final var workflowDao = new WorkflowDao(handle);
            final var activityDao = new WorkflowActivityDao(handle);

            final var abandonActivityTaskCommands = new ArrayList<AbandonActivityTaskCommand>();
            final var completeActivityTaskCommands = new ArrayList<CompleteActivityTaskCommand>();
            final var failActivityTaskCommands = new ArrayList<FailActivityTaskCommand>();
            final var abandonWorkflowTaskCommands = new ArrayList<AbandonWorkflowTaskCommand>();
            final var completeWorkflowTaskCommands = new ArrayList<CompleteWorkflowTaskCommand>();

            for (final TaskCommand command : commands) {
                switch (command) {
                    case AbandonActivityTaskCommand it -> abandonActivityTaskCommands.add(it);
                    case CompleteActivityTaskCommand it -> completeActivityTaskCommands.add(it);
                    case FailActivityTaskCommand it -> failActivityTaskCommands.add(it);
                    case AbandonWorkflowTaskCommand it -> abandonWorkflowTaskCommands.add(it);
                    case CompleteWorkflowTaskCommand it -> completeWorkflowTaskCommands.add(it);
                }
            }

            if (!abandonActivityTaskCommands.isEmpty()) {
                abandonActivityTasksInternal(activityDao, abandonActivityTaskCommands);
            }
            if (!completeActivityTaskCommands.isEmpty()) {
                completeActivityTasksInternal(workflowDao, activityDao, completeActivityTaskCommands);
            }
            if (!failActivityTaskCommands.isEmpty()) {
                failActivityTasksInternal(workflowDao, activityDao, failActivityTaskCommands);
            }
            if (!abandonWorkflowTaskCommands.isEmpty()) {
                abandonWorkflowTasksInternal(workflowDao, abandonWorkflowTaskCommands);
            }
            if (!completeWorkflowTaskCommands.isEmpty()) {
                completeWorkflowTasksInternal(workflowDao, activityDao, completeWorkflowTaskCommands, engineEvents);
            }
        });

        maybeNotifyEventListeners(engineEvents);
    }

    private void maybeNotifyEventListeners(final Collection<WorkflowEngineEvent> events) {
        if (eventListenerExecutor == null || events.isEmpty()) {
            return;
        }

        for (final WorkflowEngineEvent event : events) {
            switch (event) {
                case WorkflowRunsCompletedEvent it -> {
                    for (final WorkflowRunsCompletedEventListener listener : runsCompletedEventListeners) {
                        eventListenerExecutor.execute(() -> listener.onEvent(it));
                    }
                }
            }
        }
    }

    public List<WorkflowEvent> getRunInbox(final UUID runId) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunInbox(runId));
    }

    public List<WorkflowRunCountByNameAndStatusRow> getRunStats() {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunCountByNameAndStatus());
    }

    MetadataRegistry executorMetadataRegistry() {
        return metadataRegistry;
    }

    private Set<UUID> getPendingSubWorkflowRunIds(final WorkflowRunState run) {
        final var runIdByEventId = new HashMap<Integer, UUID>();

        Stream.concat(run.history().stream(), run.inbox().stream()).forEach(event -> {
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

    public Status status() {
        return status;
    }

    private void setStatus(final Status newStatus) {
        statusLock.lock();
        try {
            if (this.status == newStatus) {
                return;
            }

            if (this.status.canTransitionTo(newStatus)) {
                this.status = newStatus;
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from status %s to %s".formatted(this.status, newStatus));
        } finally {
            statusLock.unlock();
        }
    }

    private void requireStatusAnyOf(final Status... expectedStatuses) {
        for (final Status expectedStatus : expectedStatuses) {
            if (this.status == expectedStatus) {
                return;
            }
        }

        throw new IllegalStateException(
                "Engine must be in state any of %s, but is %s".formatted(expectedStatuses, this.status));
    }

}
