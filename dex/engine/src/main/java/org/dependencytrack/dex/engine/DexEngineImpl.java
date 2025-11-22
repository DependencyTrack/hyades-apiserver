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
package org.dependencytrack.dex.engine;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.api.ActivityExecutor;
import org.dependencytrack.dex.api.WorkflowExecutor;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.dependencytrack.dex.engine.MetadataRegistry.WorkflowMetadata;
import org.dependencytrack.dex.engine.TaskCommand.AbandonActivityTaskCommand;
import org.dependencytrack.dex.engine.TaskCommand.AbandonWorkflowTaskCommand;
import org.dependencytrack.dex.engine.TaskCommand.CompleteActivityTaskCommand;
import org.dependencytrack.dex.engine.TaskCommand.CompleteWorkflowTaskCommand;
import org.dependencytrack.dex.engine.TaskCommand.FailActivityTaskCommand;
import org.dependencytrack.dex.engine.api.ActivityTaskQueue;
import org.dependencytrack.dex.engine.api.ActivityTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.ExternalEvent;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.WorkflowTaskQueue;
import org.dependencytrack.dex.engine.api.WorkflowTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.event.DexEngineEvent;
import org.dependencytrack.dex.engine.api.event.DexEngineEventListener;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.dex.engine.api.request.CreateActivityTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.ListActivityTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.UpdateActivityTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.UpdateWorkflowTaskQueueRequest;
import org.dependencytrack.dex.engine.persistence.ActivityDao;
import org.dependencytrack.dex.engine.persistence.WorkflowDao;
import org.dependencytrack.dex.engine.persistence.WorkflowRunDao;
import org.dependencytrack.dex.engine.persistence.command.CreateActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunHistoryEntryCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunInboxEntryCommand;
import org.dependencytrack.dex.engine.persistence.command.DeleteInboxEventsCommand;
import org.dependencytrack.dex.engine.persistence.command.PollActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.PollWorkflowTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.UnlockWorkflowRunInboxEventsCommand;
import org.dependencytrack.dex.engine.persistence.command.UnlockWorkflowTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.UpdateAndUnlockRunCommand;
import org.dependencytrack.dex.engine.persistence.jdbi.JdbiFactory;
import org.dependencytrack.dex.engine.persistence.model.ActivityTaskId;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunMetadataRow;
import org.dependencytrack.dex.engine.persistence.request.GetWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.support.Buffer;
import org.dependencytrack.dex.engine.support.DefaultThreadFactory;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskCompleted;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskFailed;
import org.dependencytrack.dex.proto.event.v1.Event;
import org.dependencytrack.dex.proto.event.v1.ExternalEventReceived;
import org.dependencytrack.dex.proto.event.v1.RunCanceled;
import org.dependencytrack.dex.proto.event.v1.RunCreated;
import org.dependencytrack.dex.proto.event.v1.RunResumed;
import org.dependencytrack.dex.proto.event.v1.RunSuspended;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.eclipse.microprofile.health.HealthCheckResponse;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toTimestamp;

// TODO: Add metrics for:
//   - Workflow runs created
//   - Activities created
//   - Activities completed/failed
final class DexEngineImpl implements DexEngine {

    enum Status {

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

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(DexEngineImpl.class);

    private final DexEngineConfig config;
    private final Jdbi jdbi;
    private final ReentrantLock statusLock = new ReentrantLock();
    private final MetadataRegistry metadataRegistry = new MetadataRegistry();
    private final Map<String, TaskWorker> taskWorkerByName = new HashMap<>();
    private final List<WorkflowRunsCompletedEventListener> runsCompletedEventListeners = new ArrayList<>();

    private Status status = Status.CREATED;
    private @Nullable WorkflowTaskScheduler workflowTaskScheduler;
    private @Nullable ActivityTaskScheduler activityTaskScheduler;
    private @Nullable ExecutorService eventListenerExecutor;
    private @Nullable Buffer<ExternalEvent> externalEventBuffer;
    private @Nullable Buffer<TaskCommand> taskCommandBuffer;
    private @Nullable RetentionWorker retentionWorker;
    private @Nullable Cache<UUID, CachedWorkflowRunHistory> runHistoryCache;

    DexEngineImpl(final DexEngineConfig config) {
        this.config = requireNonNull(config);
        this.jdbi = JdbiFactory.create(config.dataSource(), config.pageTokenEncoder());
    }

    @Override
    public void start() {
        if (status == Status.RUNNING) {
            return;
        }

        setStatus(Status.STARTING);
        LOGGER.debug("Starting");

        LOGGER.debug("Initializing history cache");
        final var runHistoryCacheBuilder = Caffeine.newBuilder()
                .maximumSize(config.runHistoryCache().maxSize())
                .recordStats();
        if (config.runHistoryCache().evictAfterAccess() != null) {
            runHistoryCacheBuilder.expireAfterAccess(config.runHistoryCache().evictAfterAccess());
        }
        runHistoryCache = runHistoryCacheBuilder.build();
        new CaffeineCacheMetrics<>(runHistoryCache, "DexEngine-RunHistoryCache", null)
                .bindTo(config.meterRegistry());

        LOGGER.debug("Registering default event listeners");
        runsCompletedEventListeners.add(this::invalidateCompletedRunsHistoryCache);
        runsCompletedEventListeners.add(this::recordCompletedRunsMetrics);

        LOGGER.debug("Starting event listener executor");
        eventListenerExecutor = Executors.newSingleThreadExecutor(
                new DefaultThreadFactory("DexEngine-EventListener"));
        new ExecutorServiceMetrics(eventListenerExecutor, "DexEngine-EventListener", null)
                .bindTo(config.meterRegistry());

        if (config.workflowTaskScheduler().isEnabled()) {
            LOGGER.debug("Starting workflow task scheduler");
            workflowTaskScheduler = new WorkflowTaskScheduler(
                    jdbi,
                    config.meterRegistry(),
                    config.workflowTaskScheduler().pollInterval());
            workflowTaskScheduler.start();
        }

        if (config.activityTaskScheduler().isEnabled()) {
            LOGGER.debug("Starting activity task scheduler");
            activityTaskScheduler = new ActivityTaskScheduler(
                    jdbi,
                    config.meterRegistry(),
                    config.activityTaskScheduler().pollInterval());
            activityTaskScheduler.start();
        }

        LOGGER.debug("Starting external event buffer");
        externalEventBuffer = new Buffer<>(
                "external-event",
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
                "task-command",
                this::executeTaskCommands,
                config.taskCommandBuffer().flushInterval(),
                config.taskCommandBuffer().maxBatchSize(),
                config.meterRegistry());
        taskCommandBuffer.start();

        if (config.retention().isWorkerEnabled()) {
            LOGGER.debug("Starting retention worker");
            retentionWorker = new RetentionWorker(
                    jdbi,
                    config.retention().days(),
                    config.retention().workerInitialDelay(),
                    config.retention().workerInterval());
            retentionWorker.start();
        } else {
            LOGGER.debug("Retention worker is disabled");
        }

        for (final Map.Entry<String, TaskWorker> entry : taskWorkerByName.entrySet()) {
            LOGGER.debug("Starting task worker {}", entry.getKey());
            entry.getValue().start();
        }

        setStatus(Status.RUNNING);
        LOGGER.debug("Started");
    }

    @Override
    public void close() throws IOException {
        if (status == Status.STOPPED) {
            return;
        }

        setStatus(Status.STOPPING);
        LOGGER.debug("Stopping");

        if (retentionWorker != null) {
            LOGGER.debug("Waiting for retention worker to stop");
            retentionWorker.close();
            retentionWorker = null;
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

        if (activityTaskScheduler != null) {
            LOGGER.debug("Waiting for activity task scheduler to stop");
            activityTaskScheduler.close();
            activityTaskScheduler = null;
        }

        if (workflowTaskScheduler != null) {
            LOGGER.debug("Waiting for workflow task scheduler to stop");
            workflowTaskScheduler.close();
            workflowTaskScheduler = null;
        }

        if (taskWorkerByName != null) {
            for (final Map.Entry<String, TaskWorker> entry : taskWorkerByName.entrySet()) {
                LOGGER.debug("Waiting for task worker {} to stop", entry.getKey());
                entry.getValue().close();
            }
            taskWorkerByName.clear();
        }

        if (eventListenerExecutor != null) {
            eventListenerExecutor.close();
            eventListenerExecutor = null;
            runsCompletedEventListeners.clear();
        }

        if (runHistoryCache != null) {
            runHistoryCache.invalidateAll();
            runHistoryCache = null;
        }

        setStatus(Status.STOPPED);
        LOGGER.debug("Stopped");
    }

    @Override
    public HealthCheckResponse probeHealth() {
        final var responseBuilder = HealthCheckResponse.named("dex-engine");
        boolean isUp = this.status == Status.RUNNING;

        responseBuilder.withData("internalStatus", this.status.name());

        if (externalEventBuffer != null) {
            isUp &= externalEventBuffer.status() == Buffer.Status.RUNNING;
            responseBuilder.withData("buffer:" + externalEventBuffer.name(), externalEventBuffer.status().name());
        }
        if (taskCommandBuffer != null) {
            isUp &= taskCommandBuffer.status() == Buffer.Status.RUNNING;
            responseBuilder.withData("buffer:" + taskCommandBuffer.name(), taskCommandBuffer.status().name());
        }

        for (final Map.Entry<String, TaskWorker> entry : taskWorkerByName.entrySet()) {
            isUp &= entry.getValue().status() == TaskWorker.Status.RUNNING;
            responseBuilder.withData("taskWorker:" + entry.getKey(), entry.getValue().status().name());
        }

        return responseBuilder.status(isUp).build();
    }

    @Override
    public <A, R> void registerWorkflow(
            final WorkflowExecutor<A, R> workflowExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerWorkflow(workflowExecutor, argumentConverter, resultConverter, lockTimeout);
    }

    <A, R> void registerWorkflowInternal(
            final String workflowName,
            final int workflowVersion,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final WorkflowExecutor<A, R> workflowExecutor) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerWorkflow(workflowName, workflowVersion, argumentConverter, resultConverter, lockTimeout, workflowExecutor);
    }

    @Override
    public <A, R> void registerActivity(
            final ActivityExecutor<A, R> activityExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            boolean heartbeatEnabled) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerActivity(activityExecutor, argumentConverter, resultConverter, lockTimeout, heartbeatEnabled);
    }

    <A, R> void registerActivityInternal(
            final String activityName,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final boolean heartbeatEnabled,
            final ActivityExecutor<A, R> activityExecutor) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerActivity(activityName, argumentConverter, resultConverter, lockTimeout, heartbeatEnabled, activityExecutor);
    }

    @Override
    public void registerActivityWorker(final ActivityTaskWorkerOptions options) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);

        final var worker = new ActivityTaskWorker(
                this,
                config.activityTaskWorker().minPollInterval(),
                config.activityTaskWorker().pollBackoffIntervalFunction(),
                metadataRegistry,
                options.queueName(),
                options.maxConcurrency(),
                config.meterRegistry());

        if (taskWorkerByName.putIfAbsent(options.name(), worker) != null) {
            throw new IllegalStateException("A task worker with name %s was already registered".formatted(options.name()));
        }
    }

    @Override
    public void registerWorkflowWorker(final WorkflowTaskWorkerOptions options) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);

        final var worker = new WorkflowTaskWorker(
                this,
                metadataRegistry,
                options.queueName(),
                config.workflowTaskWorker().minPollInterval(),
                config.workflowTaskWorker().pollBackoffIntervalFunction(),
                options.maxConcurrency(),
                config.meterRegistry());

        if (taskWorkerByName.putIfAbsent(options.name(), worker) != null) {
            throw new IllegalStateException("A task worker with name %s was already registered".formatted(options.name()));
        }
    }

    @Override
    public void addEventListener(final DexEngineEventListener<?> listener) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        requireNonNull(listener, "listener must not be null");
        switch (listener) {
            case WorkflowRunsCompletedEventListener it -> runsCompletedEventListeners.add(it);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<UUID> createRuns(final Collection<CreateWorkflowRunRequest<?>> options) {
        final var now = Timestamps.now();
        final var nowInstant = toInstant(now);
        final var createWorkflowRunCommands = new ArrayList<CreateWorkflowRunCommand>(options.size());
        final var createInboxEntryCommand = new ArrayList<CreateWorkflowRunInboxEntryCommand>(options.size());

        for (final CreateWorkflowRunRequest<?> option : options) {
            @SuppressWarnings("rawtypes") final WorkflowMetadata workflowMetadata =
                    metadataRegistry.getWorkflowMetadata(option.workflowName());

            final UUID runId = timeBasedEpochRandomGenerator().generate();
            createWorkflowRunCommands.add(
                    new CreateWorkflowRunCommand(
                            runId,
                            /* parentId */ null,
                            option.workflowName(),
                            option.workflowVersion(),
                            option.queueName(),
                            option.concurrencyGroupId(),
                            option.priority(),
                            option.labels(),
                            nowInstant));

            final var runCreatedBuilder = RunCreated.newBuilder()
                    .setWorkflowName(option.workflowName())
                    .setWorkflowVersion(option.workflowVersion())
                    .setQueueName(option.queueName())
                    .setPriority(option.priority());
            if (option.concurrencyGroupId() != null) {
                runCreatedBuilder.setConcurrencyGroupId(option.concurrencyGroupId());
            }
            if (option.labels() != null) {
                runCreatedBuilder.putAllLabels(option.labels());
            }
            if (option.argument() != null) {
                final Payload argumentPayload;
                if (option.argument() instanceof final Payload payload) {
                    argumentPayload = payload;
                } else {
                    argumentPayload = workflowMetadata.argumentConverter().convertToPayload(option.argument());
                }
                runCreatedBuilder.setArgument(argumentPayload);
            }

            createInboxEntryCommand.add(
                    new CreateWorkflowRunInboxEntryCommand(
                            runId,
                            null,
                            Event.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(now)
                                    .setRunCreated(runCreatedBuilder.build())
                                    .build()));
        }

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

            return createdRunIds;
        });
    }


    @Override
    public @Nullable WorkflowRun getRun(final UUID id) {
        final List<Event> eventHistory = jdbi.withHandle(handle -> {
            final var dao = new WorkflowRunDao(handle);
            final var events = new ArrayList<Event>();

            Page<Event> eventsPage;
            String nextPageToken = null;
            do {
                eventsPage = dao.listRunEvents(
                        new ListWorkflowRunEventsRequest(id)
                                .withPageToken(nextPageToken)
                                .withLimit(25));
                nextPageToken = eventsPage.nextPageToken();
                events.addAll(eventsPage.items());
            } while (nextPageToken != null);

            return events;
        });
        if (eventHistory.isEmpty()) {
            return null;
        }

        final var runState = new WorkflowRunState(id, eventHistory);

        return new WorkflowRun(
                runState.id(),
                runState.workflowName(),
                runState.workflowVersion(),
                runState.status(),
                runState.customStatus(),
                runState.priority(),
                runState.concurrencyGroupId(),
                runState.labels(),
                runState.createdAt(),
                runState.updatedAt(),
                runState.startedAt(),
                runState.completedAt(),
                runState.argument(),
                runState.result(),
                runState.failure(),
                runState.eventHistory());
    }

    public @Nullable WorkflowRunMetadata getRunMetadata(final UUID runId) {
        final WorkflowRunMetadataRow metadataRow = jdbi.withHandle(
                handle -> new WorkflowDao(handle).getRunMetadataById(runId));
        if (metadataRow == null) {
            return null;
        }

        return new WorkflowRunMetadata(
                metadataRow.id(),
                metadataRow.workflowName(),
                metadataRow.workflowVersion(),
                metadataRow.status(),
                metadataRow.customStatus(),
                metadataRow.priority(),
                metadataRow.concurrencyGroupId(),
                metadataRow.labels(),
                metadataRow.createdAt(),
                metadataRow.updatedAt(),
                metadataRow.startedAt(),
                metadataRow.completedAt());
    }

    @Override
    public Page<WorkflowRunMetadata> listRuns(final ListWorkflowRunsRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).listRuns(request));
    }

    @Override
    public void requestRunCancellation(final UUID runId, final String reason) {
        final var cancellationEvent = Event.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunCanceled(RunCanceled.newBuilder()
                        .setReason(reason)
                        .build())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunMetadataRow runMetadata = dao.getRunMetadataById(runId);
            if (runMetadata == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (runMetadata.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            }

            final boolean hasPendingCancellation = dao.getRunInboxByRunId(runId).stream()
                    .anyMatch(Event::hasRunCanceled);
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
        final var suspensionEvent = Event.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunSuspended(RunSuspended.getDefaultInstance())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunMetadataRow runMetadata = dao.getRunMetadataById(runId);
            if (runMetadata == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (runMetadata.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            } else if (runMetadata.status() == WorkflowRunStatus.SUSPENDED) {
                throw new IllegalStateException("Workflow run %s is already suspended".formatted(runId));
            }

            final boolean hasPendingSuspension = dao.getRunInboxByRunId(runId).stream()
                    .anyMatch(Event::hasRunSuspended);
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
        final var resumeEvent = Event.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunResumed(RunResumed.getDefaultInstance())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunMetadataRow runMetadata = dao.getRunMetadataById(runId);
            if (runMetadata == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (runMetadata.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            } else if (runMetadata.status() != WorkflowRunStatus.SUSPENDED) {
                throw new IllegalStateException("Workflow run %s can not be resumed because it is not suspended".formatted(runId));
            }

            final boolean hasPendingResumption = dao.getRunInboxByRunId(runId).stream()
                    .anyMatch(Event::hasRunResumed);
            if (hasPendingResumption) {
                throw new IllegalStateException("Resumption of workflow run %s is already pending".formatted(runId));
            }

            final int createdInboxEvents = dao.createRunInboxEvents(List.of(
                    new CreateWorkflowRunInboxEntryCommand(runId, null, resumeEvent)));
            assert createdInboxEvents == 1;
        });
    }

    @Override
    public Page<Event> listRunEvents(final ListWorkflowRunEventsRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).listRunEvents(request));
    }

    @Override
    public CompletableFuture<Void> sendExternalEvent(final ExternalEvent externalEvent) {
        requireStatusAnyOf(Status.RUNNING);

        try {
            return externalEventBuffer.add(externalEvent);
        } catch (InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean createWorkflowTaskQueue(CreateWorkflowTaskQueueRequest request) {
        return jdbi.inTransaction(handle -> new WorkflowDao(handle).createWorkflowTaskQueue(request));
    }

    @Override
    public boolean updateWorkflowTaskQueue(final UpdateWorkflowTaskQueueRequest request) {
        return jdbi.inTransaction(handle -> new WorkflowDao(handle).updateWorkflowTaskQueue(request));
    }

    @Override
    public Page<WorkflowTaskQueue> listWorkflowTaskQueues(final ListWorkflowTaskQueuesRequest request) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).listWorkflowTaskQueues(request));
    }

    @Override
    public boolean createActivityTaskQueue(final CreateActivityTaskQueueRequest request) {
        return jdbi.inTransaction(handle -> new ActivityDao(handle).createActivityTaskQueue(request));
    }

    @Override
    public boolean updateActivityTaskQueue(final UpdateActivityTaskQueueRequest request) {
        return jdbi.inTransaction(handle -> new ActivityDao(handle).updateActivityTaskQueue(request));
    }

    @Override
    public Page<ActivityTaskQueue> listActivityTaskQueues(final ListActivityTaskQueuesRequest request) {
        return jdbi.withHandle(handle -> new ActivityDao(handle).listActivityTaskQueues(request));
    }

    private void flushExternalEvents(final List<ExternalEvent> externalEvents) {
        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);
            final var now = Timestamps.now();

            final var createCommands = new ArrayList<CreateWorkflowRunInboxEntryCommand>(externalEvents.size());
            for (final ExternalEvent externalEvent : externalEvents) {
                final var subjectBuilder = ExternalEventReceived.newBuilder()
                        .setId(externalEvent.eventId());
                if (externalEvent.payload() != null) {
                    subjectBuilder.setPayload(externalEvent.payload());
                }

                createCommands.add(
                        new CreateWorkflowRunInboxEntryCommand(
                                externalEvent.workflowRunId(),
                                null,
                                Event.newBuilder()
                                        .setId(-1)
                                        .setTimestamp(now)
                                        .setExternalEventReceived(subjectBuilder)
                                        .build()));
            }

            dao.createRunInboxEvents(createCommands);
        });
    }

    List<WorkflowTask> pollWorkflowTasks(
            final String queueName,
            final Collection<PollWorkflowTaskCommand> commands,
            final int limit) {
        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            // TODO: We could introduce stickyness to workflow runs, such that the same run will be processed
            //  by the same worker instance for at least a certain amount of time.
            //  This would makes caches more efficient. Currently each instance collaborating on processing
            //  a given workflow run will maintain its own cache.

            final Map<UUID, PolledWorkflowTask> polledTaskByRunId =
                    dao.pollAndLockWorkflowTasks(this.config.instanceId(), queueName, commands, limit);
            if (polledTaskByRunId.isEmpty()) {
                return Collections.emptyList();
            }

            final var historyRequests = new ArrayList<GetWorkflowRunHistoryRequest>(polledTaskByRunId.size());
            final var cachedHistoryByRunId = new HashMap<UUID, List<Event>>(polledTaskByRunId.size());

            // Try to populate event histories from cache first.
            for (final UUID runId : polledTaskByRunId.keySet()) {
                final CachedWorkflowRunHistory cachedHistory = runHistoryCache.getIfPresent(runId);
                if (cachedHistory == null) {
                    // Cache miss; Load the entire history.
                    historyRequests.add(new GetWorkflowRunHistoryRequest(runId, -1));
                } else {
                    // Cache hit; Only load new history events.
                    cachedHistoryByRunId.put(runId, cachedHistory.events());
                    historyRequests.add(new GetWorkflowRunHistoryRequest(runId, cachedHistory.maxSequenceNumber()));
                }
            }

            final Map<UUID, PolledWorkflowEvents> polledEventsByRunId =
                    dao.pollRunEvents(config.instanceId(), historyRequests);

            return polledTaskByRunId.values().stream()
                    .map(polledTask -> {
                        final PolledWorkflowEvents polledEvents = polledEventsByRunId.get(polledTask.runId());
                        final List<Event> cachedHistoryEvents = cachedHistoryByRunId.get(polledTask.runId());

                        var historySize = polledEvents.history().size();
                        if (cachedHistoryEvents != null) {
                            historySize += cachedHistoryEvents.size();
                        }

                        final var history = new ArrayList<Event>(historySize);
                        if (cachedHistoryEvents != null) {
                            history.addAll(cachedHistoryEvents);
                        }
                        history.addAll(polledEvents.history());

                        runHistoryCache.put(
                                polledTask.runId(),
                                new CachedWorkflowRunHistory(
                                        history,
                                        polledEvents.maxHistoryEventSequenceNumber()));

                        return new WorkflowTask(
                                polledTask.runId(),
                                polledTask.workflowName(),
                                polledTask.workflowVersion(),
                                polledTask.queueName(),
                                polledTask.concurrencyGroupId(),
                                polledTask.priority(),
                                polledTask.labels(),
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

        final int unlockedWorkflowRuns = dao.unlockWorkflowTasks(
                this.config.instanceId(),
                abandonCommands.stream()
                        .map(abandonCommand -> new UnlockWorkflowTaskCommand(
                                abandonCommand.task().queueName(),
                                abandonCommand.task().workflowRunId()))
                        .toList());
        assert unlockedWorkflowRuns == abandonCommands.size();
    }

    CompletableFuture<Void> completeWorkflowTask(
            final WorkflowRunState workflowRunState) throws InterruptedException, TimeoutException {
        return taskCommandBuffer.add(new CompleteWorkflowTaskCommand(workflowRunState));
    }

    private void completeWorkflowTasksInternal(
            final WorkflowDao workflowDao,
            final ActivityDao activityDao,
            final Collection<CompleteWorkflowTaskCommand> commands,
            final Collection<DexEngineEvent> engineEvents) {
        final List<WorkflowRunState> actionableRuns = commands.stream()
                .map(CompleteWorkflowTaskCommand::workflowRunState)
                .collect(Collectors.toList());

        final List<UUID> updatedRunIds = workflowDao.updateAndUnlockRuns(
                this.config.instanceId(),
                actionableRuns.stream()
                        .map(run -> new UpdateAndUnlockRunCommand(
                                run.id(),
                                run.queueName(),
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
            for (final UUID runId : notUpdatedRunIds) {
                LOGGER.warn("""
                        Workflow run {} was not updated, indicating modification \
                        by another worker instance""", runId);
            }

            // Since we lost the lock on these runs, we can't act upon them anymore.
            // Note that this is expected behavior and not necessarily reason for concern.
            actionableRuns.removeIf(run -> notUpdatedRunIds.contains(run.id()));
        }

        final var createHistoryEntryCommands = new ArrayList<CreateWorkflowRunHistoryEntryCommand>(commands.size() * 2);
        final var createInboxEntryCommands = new ArrayList<CreateWorkflowRunInboxEntryCommand>(commands.size() * 2);
        final var createWorkflowRunCommands = new ArrayList<CreateWorkflowRunCommand>();
        final var continuedAsNewRunIds = new ArrayList<UUID>();
        final var createActivityTaskCommands = new ArrayList<CreateActivityTaskCommand>();
        final var completedRuns = new ArrayList<WorkflowRunMetadata>();

        for (final WorkflowRunState run : actionableRuns) {
            if (!runsCompletedEventListeners.isEmpty() && run.status().isTerminal()) {
                completedRuns.add(new WorkflowRunMetadata(
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

            // Write all processed events to history.
            int sequenceNumber = run.eventHistory().size();
            for (final Event newEvent : run.newEvents()) {
                createHistoryEntryCommands.add(
                        new CreateWorkflowRunHistoryEntryCommand(
                                run.id(),
                                sequenceNumber++,
                                newEvent));
            }

            for (final Event newEvent : run.pendingTimerElapsedEvents()) {
                createInboxEntryCommands.add(
                        new CreateWorkflowRunInboxEntryCommand(
                                run.id(),
                                toInstant(newEvent.getTimerElapsed().getElapseAt()),
                                newEvent));
            }

            final var now = Timestamps.now();
            final var nowInstant = toInstant(now);

            for (final WorkflowRunMessage message : run.pendingWorkflowMessages()) {
                // If the outbound message is a RunCreated event, the recipient
                // workflow run will need to be created first.
                boolean shouldCreateWorkflowRun = message.event().hasRunCreated();

                // If this is the run re-scheduling itself as part of he "continue as new"
                // mechanism, no new run needs to be created.
                shouldCreateWorkflowRun &= !(run.continuedAsNew() && message.recipientRunId().equals(run.id()));

                if (shouldCreateWorkflowRun) {
                    createWorkflowRunCommands.add(
                            new CreateWorkflowRunCommand(
                                    message.recipientRunId(),
                                    /* parentId */ run.id(),
                                    message.event().getRunCreated().getWorkflowName(),
                                    message.event().getRunCreated().getWorkflowVersion(),
                                    message.event().getRunCreated().getQueueName(),
                                    message.event().getRunCreated().hasConcurrencyGroupId()
                                            ? message.event().getRunCreated().getConcurrencyGroupId()
                                            : null,
                                    message.event().getRunCreated().getPriority(),
                                    message.event().getRunCreated().getLabelsCount() > 0
                                            ? Map.copyOf(message.event().getRunCreated().getLabelsMap())
                                            : null,
                                    nowInstant));
                }

                createInboxEntryCommands.add(
                        new CreateWorkflowRunInboxEntryCommand(
                                message.recipientRunId(),
                                toInstant(message.event().getTimestamp()),
                                message.event()));
            }

            // If there are pending sub workflow runs, make sure those are canceled, too.
            if (run.status() == WorkflowRunStatus.CANCELED) {
                for (final UUID childRunId : getPendingChildRunIds(run)) {
                    createInboxEntryCommands.add(
                            new CreateWorkflowRunInboxEntryCommand(
                                    childRunId,
                                    /* visibleFrom */ null,
                                    Event.newBuilder()
                                            .setId(-1)
                                            .setTimestamp(now)
                                            .setRunCanceled(RunCanceled.newBuilder()
                                                    .setReason("Parent canceled")
                                                    .build())
                                            .build()));
                }
            }

            for (final Event newEvent : run.pendingActivityTaskCreatedEvents()) {
                createActivityTaskCommands.add(
                        new CreateActivityTaskCommand(
                                run.id(),
                                newEvent.getId(),
                                newEvent.getActivityTaskCreated().getName(),
                                newEvent.getActivityTaskCreated().getQueueName(),
                                newEvent.getActivityTaskCreated().getPriority(),
                                newEvent.getActivityTaskCreated().hasArgument()
                                        ? newEvent.getActivityTaskCreated().getArgument()
                                        : null,
                                newEvent.getActivityTaskCreated().hasScheduledFor()
                                        ? toInstant(newEvent.getActivityTaskCreated().getScheduledFor())
                                        : null));
            }

            if (run.continuedAsNew()) {
                continuedAsNewRunIds.add(run.id());
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

        if (!completedRuns.isEmpty()) {
            engineEvents.add(new WorkflowRunsCompletedEvent(completedRuns));
        }
    }

    List<ActivityTask> pollActivityTasks(
            final String queueName,
            final Collection<PollActivityTaskCommand> commands,
            final int limit) {
        return jdbi.inTransaction(handle -> {
            final var activityDao = new ActivityDao(handle);

            return activityDao.pollAndLockActivityTasks(
                            this.config.instanceId(),
                            queueName,
                            commands,
                            limit).stream()
                    .map(polledTask -> new ActivityTask(
                            polledTask.workflowRunId(),
                            polledTask.createdEventId(),
                            polledTask.activityName(),
                            polledTask.queueName(),
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
            final ActivityDao activityDao,
            final Collection<AbandonActivityTaskCommand> commands) {
        final int abandonedTasks = activityDao.unlockActivityTasks(
                this.config.instanceId(),
                commands.stream()
                        .map(command -> new ActivityTaskId(
                                command.task().queueName(),
                                command.task().workflowRunId(),
                                command.task().createdEventId()))
                        .toList());
        assert abandonedTasks == commands.size()
                : "Abandoned tasks: actual=%d, expected=%d".formatted(abandonedTasks, 1);
    }

    CompletableFuture<Void> completeActivityTask(
            final ActivityTask task, final @Nullable Payload result) throws InterruptedException, TimeoutException {
        return taskCommandBuffer.add(new CompleteActivityTaskCommand(task, result, Instant.now()));
    }

    CompletableFuture<Void> failActivityTask(
            final ActivityTask task, final Throwable exception) throws InterruptedException, TimeoutException {
        return taskCommandBuffer.add(new FailActivityTaskCommand(task, exception, Instant.now()));
    }

    private void completeActivityTasksInternal(
            final WorkflowDao workflowDao,
            final ActivityDao activityDao,
            final Collection<CompleteActivityTaskCommand> commands) {
        final var tasksToDelete = new ArrayList<ActivityTaskId>(commands.size());
        final var inboxEventsToCreate = new ArrayList<CreateWorkflowRunInboxEntryCommand>(commands.size());

        for (final CompleteActivityTaskCommand command : commands) {
            tasksToDelete.add(new ActivityTaskId(
                    command.task().queueName(),
                    command.task().workflowRunId(),
                    command.task().createdEventId()));

            final var taskCompletedBuilder = ActivityTaskCompleted.newBuilder()
                    .setActivityTaskCreatedEventId(command.task().createdEventId());
            if (command.result() != null) {
                taskCompletedBuilder.setResult(command.result());
            }
            inboxEventsToCreate.add(
                    new CreateWorkflowRunInboxEntryCommand(
                            command.task().workflowRunId(),
                            null,
                            Event.newBuilder()
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
            final ActivityDao activityDao,
            final Collection<FailActivityTaskCommand> commands) {
        final var tasksToDelete = new ArrayList<ActivityTaskId>(commands.size());
        final var inboxEventsToCreate = new ArrayList<CreateWorkflowRunInboxEntryCommand>(commands.size());

        for (final FailActivityTaskCommand command : commands) {
            tasksToDelete.add(new ActivityTaskId(
                    command.task().queueName(),
                    command.task().workflowRunId(),
                    command.task().createdEventId()));

            inboxEventsToCreate.add(
                    new CreateWorkflowRunInboxEntryCommand(
                            command.task().workflowRunId(),
                            /* visibleFrom */ null,
                            Event.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(toTimestamp(command.timestamp()))
                                    .setActivityTaskFailed(ActivityTaskFailed.newBuilder()
                                            .setActivityTaskCreatedEventId(command.task().createdEventId())
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
            final Instant newLockedUntil = new ActivityDao(handle).extendActivityTaskLock(
                    this.config.instanceId(), taskId, lockTimeout);
            if (newLockedUntil == null) {
                throw new IllegalStateException(
                        "Lock of activity task %s was not extended; Did we lose the lock already?".formatted(taskId));
            }

            return newLockedUntil;
        });
    }

    private void executeTaskCommands(final List<TaskCommand> commands) {
        final var engineEvents = new ArrayList<DexEngineEvent>();

        jdbi.useTransaction(handle -> {
            final var workflowDao = new WorkflowDao(handle);
            final var activityDao = new ActivityDao(handle);

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

    private void maybeNotifyEventListeners(final Collection<DexEngineEvent> events) {
        if (eventListenerExecutor == null || events.isEmpty()) {
            return;
        }

        for (final DexEngineEvent event : events) {
            switch (event) {
                case WorkflowRunsCompletedEvent it -> {
                    for (final WorkflowRunsCompletedEventListener listener : runsCompletedEventListeners) {
                        eventListenerExecutor.execute(() -> listener.onEvent(it));
                    }
                }
            }
        }
    }

    public List<WorkflowRunCountByNameAndStatusRow> getRunStats() {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunCountByNameAndStatus());
    }

    MetadataRegistry executorMetadataRegistry() {
        return metadataRegistry;
    }

    private Set<UUID> getPendingChildRunIds(final WorkflowRunState run) {
        final var runIdByEventId = new HashMap<Integer, UUID>();

        Stream.concat(run.eventHistory().stream(), run.newEvents().stream()).forEach(event -> {
            switch (event.getSubjectCase()) {
                case CHILD_RUN_CREATED -> {
                    final String runId = event.getChildRunCreated().getRunId();
                    runIdByEventId.put(event.getId(), UUID.fromString(runId));
                }
                case CHILD_RUN_COMPLETED -> {
                    final int createdEventId = event.getChildRunCompleted().getChildRunCreatedEventId();
                    runIdByEventId.remove(createdEventId);
                }
                case CHILD_RUN_FAILED -> {
                    final int createdEventId = event.getChildRunFailed().getChildRunCreatedEventId();
                    runIdByEventId.remove(createdEventId);
                }
            }
        });

        return Set.copyOf(runIdByEventId.values());
    }

    private void invalidateCompletedRunsHistoryCache(final WorkflowRunsCompletedEvent event) {
        if (runHistoryCache == null) {
            return;
        }

        runHistoryCache.invalidateAll(
                event.completedRuns().stream()
                        .map(WorkflowRunMetadata::id)
                        .collect(Collectors.toSet()));
    }

    private void recordCompletedRunsMetrics(final WorkflowRunsCompletedEvent event) {
        for (final WorkflowRunMetadata completedRun : event.completedRuns()) {
            final var tags = List.of(
                    Tag.of("workflowName", completedRun.workflowName()),
                    Tag.of("workflowVersion", String.valueOf(completedRun.workflowVersion())),
                    Tag.of("status", completedRun.status().toString()));

            config.meterRegistry().counter("dt.dex.engine.runs.completed", tags).increment();
        }
    }

    Status status() {
        return status;
    }

    private void setStatus(final Status newStatus) {
        statusLock.lock();
        try {
            if (this.status == newStatus) {
                return;
            }

            if (this.status.canTransitionTo(newStatus)) {
                LOGGER.info("Transitioning from status {} to {}", this.status, newStatus);
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
