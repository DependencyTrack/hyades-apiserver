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
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.api.proto.v1.ActivityTaskCompleted;
import org.dependencytrack.workflow.api.proto.v1.ActivityTaskFailed;
import org.dependencytrack.workflow.api.proto.v1.ExternalEventReceived;
import org.dependencytrack.workflow.api.proto.v1.RunCancelled;
import org.dependencytrack.workflow.api.proto.v1.RunResumed;
import org.dependencytrack.workflow.api.proto.v1.RunScheduled;
import org.dependencytrack.workflow.api.proto.v1.RunSuspended;
import org.dependencytrack.workflow.api.proto.v1.WorkflowEvent;
import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;
import org.dependencytrack.workflow.engine.TaskCommand.AbandonActivityTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.AbandonWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.CompleteActivityTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.CompleteWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.TaskCommand.FailActivityTaskCommand;
import org.dependencytrack.workflow.engine.api.ActivityGroup;
import org.dependencytrack.workflow.engine.api.CreateWorkflowRunRequest;
import org.dependencytrack.workflow.engine.api.CreateWorkflowScheduleRequest;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowGroup;
import org.dependencytrack.workflow.engine.api.WorkflowSchedule;
import org.dependencytrack.workflow.engine.persistence.JdbiFactory;
import org.dependencytrack.workflow.engine.persistence.WorkflowActivityDao;
import org.dependencytrack.workflow.engine.persistence.WorkflowDao;
import org.dependencytrack.workflow.engine.persistence.WorkflowRunDao;
import org.dependencytrack.workflow.engine.persistence.WorkflowScheduleDao;
import org.dependencytrack.workflow.engine.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.engine.persistence.model.DeleteInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.model.GetWorkflowRunJournalRequest;
import org.dependencytrack.workflow.engine.persistence.model.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowRunInboxRow;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowRunJournalRow;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowScheduleRow;
import org.dependencytrack.workflow.engine.persistence.model.PollActivityTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.PollWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.UnlockWorkflowRunInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowConcurrencyGroupRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRowUpdate;
import org.dependencytrack.workflow.engine.persistence.pagination.Page;
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

        CREATED(1),  // 0
        STARTING(2), // 1
        RUNNING(3),  // 2
        STOPPING(4), // 3
        STOPPED(1);  // 4

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

    private record CachedWorkflowRunJournal(List<WorkflowEvent> events, int maxSequenceNumber) {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineImpl.class);

    private final WorkflowEngineConfig config;
    private final Jdbi jdbi;
    private final ReentrantLock statusLock = new ReentrantLock();
    private final ExecutorMetadataRegistry executorMetadataRegistry = new ExecutorMetadataRegistry();
    private Status status = Status.CREATED;
    @Nullable private ExecutorService taskDispatcherExecutor;
    @Nullable private Map<String, ExecutorService> executorServiceByName;
    @Nullable private ScheduledExecutorService schedulerExecutor;
    @Nullable private ScheduledExecutorService retentionExecutor;
    @Nullable private Buffer<NewExternalEvent> externalEventBuffer;
    @Nullable private Buffer<TaskCommand> taskCommandBuffer;
    @Nullable private Cache<UUID, CachedWorkflowRunJournal> cachedJournalByRunId;

    WorkflowEngineImpl(final WorkflowEngineConfig config) {
        this.config = requireNonNull(config);
        this.jdbi = JdbiFactory.create(config.dataSource());
    }

    @Override
    public void start() {
        setStatus(Status.STARTING);
        LOGGER.debug("Starting");

        LOGGER.debug("Initializing journal cache");
        final var journalCacheBuilder = Caffeine.newBuilder()
                .maximumSize(config.runJournalCache().maxSize());
        if (config.runJournalCache().evictAfterAccess() != null) {
            journalCacheBuilder.expireAfterAccess(config.runJournalCache().evictAfterAccess());
        }
        if (config.meterRegistry() != null) {
            journalCacheBuilder.recordStats();
        }
        cachedJournalByRunId = journalCacheBuilder.build();
        if (config.meterRegistry() != null) {
            new CaffeineCacheMetrics<>(cachedJournalByRunId, "WorkflowEngine-RunJournalCache", null);
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

        if (cachedJournalByRunId != null) {
            cachedJournalByRunId.invalidateAll();
            cachedJournalByRunId = null;
        }

        setStatus(Status.STOPPED);
        LOGGER.debug("Stopped");
    }

    /**
     * Register a {@link WorkflowExecutor} with the engine.
     * <p>
     * The executor's class <strong>must</strong> be annotated with {@link Workflow}.
     *
     * @param workflowExecutor  The {@link WorkflowExecutor} to register.
     * @param argumentConverter {@link PayloadConverter} for the argument of the workflow.
     * @param resultConverter   {@link PayloadConverter} for the result of the workflow.
     * @param lockTimeout       For how long workflow runs should be locked.
     * @param <A>               Type of the workflow's argument.
     * @param <R>               Type of the workflow's result.
     */
    @Override
    public <A, R> void register(
            final WorkflowExecutor<A, R> workflowExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        executorMetadataRegistry.register(workflowExecutor, argumentConverter, resultConverter, lockTimeout);
    }

    <A, R> void register(
            final String workflowName,
            final int workflowVersion,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final WorkflowExecutor<A, R> workflowExecutor) {
        executorMetadataRegistry.register(workflowName, workflowVersion, argumentConverter, resultConverter, lockTimeout, workflowExecutor);
    }

    /**
     * Register an {@link ActivityExecutor} with the engine.
     * <p>
     * The executor's class <strong>must</strong> be annotated with {@link Activity}.
     *
     * @param activityExecutor  The {@link ActivityExecutor} to register.
     * @param argumentConverter {@link PayloadConverter} for the argument of the activity.
     * @param resultConverter   {@link PayloadConverter} for the result of the activity.
     * @param lockTimeout       For how long activity instances should be locked.
     * @param <A>               Type of the activity's argument.
     * @param <R>               Type of the activity's result.
     */
    @Override
    public <A, R> void register(
            final ActivityExecutor<A, R> activityExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        executorMetadataRegistry.register(activityExecutor, argumentConverter, resultConverter, lockTimeout);
    }

    <A, R> void register(
            final String activityName,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final boolean heartbeatEnabled,
            final ActivityExecutor<A, R> activityExecutor) {
        executorMetadataRegistry.register(activityName, argumentConverter, resultConverter, lockTimeout, heartbeatEnabled, activityExecutor);
    }

    /**
     * Mounts a {@link WorkflowGroup} to the engine.
     * <p>
     * All workflows in the provided group <strong>must</strong> have been registered with the engine before.
     *
     * @param group The {@link WorkflowGroup} to mount.
     * @throws IllegalStateException When any of the workflows within the group have not been registered,
     *                               or another {@link WorkflowGroup} with the same name is already mounted.
     */
    @Override
    public void mount(final WorkflowGroup group) {
        requireRunningStatus();
        LOGGER.debug("Mounting {}", group);

        for (final String workflowName : group.workflowNames()) {
            try {
                executorMetadataRegistry.getWorkflowMetadata(workflowName);
            } catch (NoSuchElementException e) {
                throw new IllegalStateException("Workflow %s is not registered".formatted(workflowName), e);
            }
        }

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
                new WorkflowTaskManager(this, group, executorMetadataRegistry),
                group.maxConcurrency(),
                config.workflowTaskDispatcher().minPollInterval(),
                config.workflowTaskDispatcher().pollBackoffIntervalFunction(),
                config.meterRegistry());

        taskDispatcherExecutor.execute(taskDispatcher);
    }

    @Override
    public void mount(final ActivityGroup group) {
        requireRunningStatus();
        LOGGER.debug("Mounting {}", group);

        for (final String activityName : group.activityNames()) {
            try {
                executorMetadataRegistry.getActivityMetadata(activityName);
            } catch (NoSuchElementException e) {
                throw new IllegalStateException("Activity %s is not registered".formatted(activityName), e);
            }
        }

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
                new ActivityTaskManager(this, group, executorMetadataRegistry),
                group.maxConcurrency(),
                config.activityTaskDispatcher().minPollInterval(),
                config.activityTaskDispatcher().pollBackoffIntervalFunction(),
                config.meterRegistry());

        taskDispatcherExecutor.execute(taskDispatcher);
    }

    @Override
    public List<UUID> createRuns(final Collection<CreateWorkflowRunRequest> options) {
        requireRunningStatus();

        final var now = Timestamps.now();
        final var newWorkflowRunRows = new ArrayList<NewWorkflowRunRow>(options.size());
        final var newInboxEventRows = new ArrayList<NewWorkflowRunInboxRow>(options.size());
        final var nextRunIdByConcurrencyGroupId = new HashMap<String, UUID>();

        for (final CreateWorkflowRunRequest option : options) {
            final UUID runId = randomUUIDv7();
            newWorkflowRunRows.add(
                    new NewWorkflowRunRow(
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
                runScheduledBuilder.setArgument(option.argument());
            }

            newInboxEventRows.add(
                    new NewWorkflowRunInboxRow(runId, null,
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

    @Override
    public void requestRunCancellation(final UUID runId, final String reason) {
        final var cancellationEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunCancelled(RunCancelled.newBuilder()
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
                    .anyMatch(WorkflowEvent::hasRunCancelled);
            if (hasPendingCancellation) {
                throw new IllegalStateException("Cancellation of workflow run %s already pending".formatted(runId));
            }

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new NewWorkflowRunInboxRow(runId, null, cancellationEvent)));
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
                    new NewWorkflowRunInboxRow(runId, null, suspensionEvent)));
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
                    new NewWorkflowRunInboxRow(runId, null, resumeEvent)));
            assert createdInboxEvents == 1;
        });
    }

    @Override
    public CompletableFuture<Void> sendExternalEvent(
            final UUID workflowRunId,
            final String eventId,
            final WorkflowPayload content) {
        requireRunningStatus();

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
            final var schedulesToCreate = new ArrayList<NewWorkflowScheduleRow>(requests.size());

            for (final CreateWorkflowScheduleRequest newSchedule : requests) {
                final Schedule cronSchedule;
                try {
                    cronSchedule = Schedule.create(newSchedule.cron());
                } catch (InvalidExpressionException e) {
                    throw new IllegalArgumentException("Cron expression %s of schedule %s is invalid".formatted(
                            newSchedule.cron(), newSchedule.name()), e);
                }

                final Instant nextFireAt;
                if (newSchedule.initialDelay() == null) {
                    nextFireAt = cronSchedule.next(Date.from(now)).toInstant();
                } else {
                    nextFireAt = now.plus(newSchedule.initialDelay());
                }

                schedulesToCreate.add(new NewWorkflowScheduleRow(
                        newSchedule.name(),
                        newSchedule.cron(),
                        newSchedule.workflowName(),
                        newSchedule.workflowVersion(),
                        newSchedule.concurrencyGroupId(),
                        newSchedule.priority(),
                        newSchedule.labels(),
                        newSchedule.argument(),
                        nextFireAt));
            }

            return dao.createSchedules(schedulesToCreate);
        });
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

            final var journalRequests = new ArrayList<GetWorkflowRunJournalRequest>(polledRunById.size());
            final var cachedJournalEventsByRunId = new HashMap<UUID, List<WorkflowEvent>>(polledRunById.size());
            for (final UUID runId : polledRunById.keySet()) {
                final CachedWorkflowRunJournal cachedJournal = cachedJournalByRunId.getIfPresent(runId);
                if (cachedJournal == null) {
                    journalRequests.add(new GetWorkflowRunJournalRequest(runId, -1));
                } else {
                    cachedJournalEventsByRunId.put(runId, cachedJournal.events());
                    journalRequests.add(new GetWorkflowRunJournalRequest(runId, cachedJournal.maxSequenceNumber()));
                }
            }

            final Map<UUID, PolledWorkflowEvents> polledEventsByRunId =
                    dao.pollRunEvents(this.config.instanceId(), journalRequests);

            return polledRunById.values().stream()
                    .map(polledRun -> {
                        final PolledWorkflowEvents polledEvents = polledEventsByRunId.get(polledRun.id());
                        final List<WorkflowEvent> cachedJournalEvents = cachedJournalEventsByRunId.get(polledRun.id());

                        final var journal = new ArrayList<WorkflowEvent>(
                                polledEvents.journal().size()
                                + (cachedJournalEvents != null ? cachedJournalEvents.size() : 0));
                        if (cachedJournalEvents != null) {
                            journal.addAll(cachedJournalEvents);
                        }
                        journal.addAll(polledEvents.journal());

                        cachedJournalByRunId.put(polledRun.id(), new CachedWorkflowRunJournal(
                                journal, polledEvents.maxJournalEventSequenceNumber()));

                        return new WorkflowTask(
                                polledRun.id(),
                                polledRun.workflowName(),
                                polledRun.workflowVersion(),
                                polledRun.concurrencyGroupId(),
                                polledRun.priority(),
                                polledRun.labels(),
                                polledEvents.maxInboxEventDequeueCount(),
                                journal,
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
            final Collection<CompleteWorkflowTaskCommand> commands) {
        final List<WorkflowRunState> actionableRuns = commands.stream()
                .map(CompleteWorkflowTaskCommand::workflowRunState)
                .collect(Collectors.toList());

        final List<UUID> updatedRunIds = workflowDao.updateRuns(
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

        final var newJournalEntries = new ArrayList<NewWorkflowRunJournalRow>(commands.size() * 2);
        final var newInboxEvents = new ArrayList<NewWorkflowRunInboxRow>(commands.size() * 2);
        final var newWorkflowRuns = new ArrayList<NewWorkflowRunRow>();
        final var continuedAsNewRunIds = new ArrayList<UUID>();
        final var newActivityTasks = new ArrayList<NewActivityTaskRow>();
        final var nextRunIdByNewConcurrencyGroupId = new HashMap<String, UUID>();
        final var concurrencyGroupsToUpdate = new HashSet<String>();

        for (final WorkflowRunState run : actionableRuns) {
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
                boolean shouldCreateWorkflowRun = message.event().hasRunScheduled();

                // If this is the run re-scheduling itself as part of he "continue as new"
                // mechanism, no new run needs to be created.
                shouldCreateWorkflowRun &= !(run.continuedAsNew() && message.recipientRunId().equals(run.id()));

                if (shouldCreateWorkflowRun) {
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

            if (run.continuedAsNew()) {
                continuedAsNewRunIds.add(run.id());
            }

            if (run.status().isTerminal() && run.concurrencyGroupId().isPresent()) {
                concurrencyGroupsToUpdate.add(run.concurrencyGroupId().get());
            }
        }

        if (!continuedAsNewRunIds.isEmpty()) {
            workflowDao.truncateRunJournals(continuedAsNewRunIds);
        }

        if (!newJournalEntries.isEmpty()) {
            final int journalEntriesCreated = workflowDao.createRunJournalEntries(newJournalEntries);
            assert journalEntriesCreated == newJournalEntries.size()
                    : "Created journal entries: actual=%d, expected=%d".formatted(
                    journalEntriesCreated, newJournalEntries.size());
        }

        if (!newWorkflowRuns.isEmpty()) {
            // TODO: Call ScheduleWorkflowRuns instead so concurrency groups are updated, too.
            //  Ensure it can participate in this transaction!
            final List<UUID> createdRunIds = workflowDao.createRuns(newWorkflowRuns);
            assert createdRunIds.size() == newWorkflowRuns.size()
                    : "Created runs: actual=%d, expected=%d".formatted(
                    createdRunIds.size(), newWorkflowRuns.size());
        }

        if (!newInboxEvents.isEmpty()) {
            final int createdInboxEvents = workflowDao.createRunInboxEvents(newInboxEvents);
            assert createdInboxEvents == newInboxEvents.size()
                    : "Created inbox events: actual=%d, expected=%d".formatted(
                    createdInboxEvents, newInboxEvents.size());
        }

        if (!newActivityTasks.isEmpty()) {
            final int createdActivityTasks = activityDao.createActivityTasks(newActivityTasks);
            assert createdActivityTasks == newActivityTasks.size()
                    : "Created activity tasks: actual=%d, expected=%d".formatted(
                    createdActivityTasks, newActivityTasks.size());
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
        final var inboxEventsToCreate = new ArrayList<NewWorkflowRunInboxRow>(commands.size());

        for (final CompleteActivityTaskCommand command : commands) {
            tasksToDelete.add(new ActivityTaskId(command.task().workflowRunId(), command.task().scheduledEventId()));

            final var taskCompletedBuilder = ActivityTaskCompleted.newBuilder()
                    .setTaskScheduledEventId(command.task().scheduledEventId());
            if (command.result() != null) {
                taskCompletedBuilder.setResult(command.result());
            }
            inboxEventsToCreate.add(new NewWorkflowRunInboxRow(
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
        final var inboxEventsToCreate = new ArrayList<NewWorkflowRunInboxRow>(commands.size());

        for (final FailActivityTaskCommand command : commands) {
            tasksToDelete.add(new ActivityTaskId(command.task().workflowRunId(), command.task().scheduledEventId()));

            inboxEventsToCreate.add(new NewWorkflowRunInboxRow(
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
                completeWorkflowTasksInternal(workflowDao, activityDao, completeWorkflowTaskCommands);
            }
        });
    }

    @Nullable
    public WorkflowRunStateProjection getRun(final UUID runId) {
        return jdbi.withHandle(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunRow runRow = dao.getRun(runId);
            if (runRow == null) {
                return null;
            }

            final List<WorkflowEvent> runJournal = dao.getRunJournal(runId);

            final var runState = new WorkflowRunState(
                    runRow.id(),
                    runRow.workflowName(),
                    runRow.workflowVersion(),
                    runRow.concurrencyGroupId(),
                    runJournal);

            return WorkflowRunStateProjection.of(runState);
        });
    }

    public Page<WorkflowRunRow> listRuns(final ListWorkflowRunsRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).listRuns(request));
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

    ExecutorMetadataRegistry executorMetadataRegistry() {
        return executorMetadataRegistry;
    }

    private Set<UUID> getPendingSubWorkflowRunIds(final WorkflowRunState run) {
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
                    "Can not transition from state %s to %s".formatted(this.status, newStatus));
        } finally {
            statusLock.unlock();
        }
    }

    private void requireRunningStatus() {
        if (!Status.RUNNING.equals(status)) {
            throw new IllegalStateException(
                    "Engine must be in state %s, but is %s".formatted(Status.RUNNING, this));
        }
    }

    static UUID randomUUIDv7() {
        // UUIDv7 cause BTREE indexes (i.e., primary keys) to bloat less than other UUID versions,
        // because they're time-sortable.
        // https://antonz.org/uuidv7/
        // https://maciejwalkowiak.com/blog/postgres-uuid-primary-key/
        return timeBasedEpochRandomGenerator().generate();
    }

}
