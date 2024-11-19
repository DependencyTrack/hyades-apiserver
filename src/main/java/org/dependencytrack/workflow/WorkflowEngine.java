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
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.v1alpha1.RunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.workflow.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventInboxRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventLogRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunRow;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

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

        private boolean isCreatedOrStopped() {
            return equals(CREATED) || equals(STOPPED);
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
    private static final WorkflowEngine INSTANCE = new WorkflowEngine();

    private final UUID instanceId = UUID.randomUUID();
    private final ReentrantLock stateLock = new ReentrantLock();
    private State state = State.CREATED;
    private ExecutorService dispatcherExecutor;
    private Map<String, ExecutorService> executorServiceByName;

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

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

        setState(State.STOPPED);
    }

    public <A, R> void registerWorkflowRunner(
            final String workflowName,
            final WorkflowRunner<A, R> workflowRunner,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        state.assertRunning();

        if (executorServiceByName.containsKey(workflowName)) {
            throw new IllegalStateException();
        }

        // TODO: Use virtual threads?
        final ExecutorService executorService = Executors.newFixedThreadPool(maxConcurrency,
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-WorkflowRunner-" + workflowName + "-%d")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-WorkflowRunner-" + workflowName, null)
                    .bindTo(Metrics.getRegistry());
        }
        executorServiceByName.put(workflowName, executorService);

        dispatcherExecutor.execute(new WorkflowTaskDispatcher<>(
                this, executorService, workflowName, workflowRunner, argumentConverter, resultConverter, maxConcurrency));
    }

    public UUID scheduleWorkflowRun(final String workflowName, final int workflowVersion) {
        state.assertRunning();

        final var runId = UUID.randomUUID();
        final var executionStartedEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunStarted(RunStarted.newBuilder()
                        .setWorkflowName(workflowName)
                        .setWorkflowVersion(workflowVersion)
                        .build())
                .build();

        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunRow runRow = dao.createWorkflowRun(
                    new NewWorkflowRunRow(runId, workflowName, workflowVersion, null));
            assert runRow != null;

            final int createdInboxEvents = dao.createInboxEvents(List.of(
                    new NewWorkflowEventInboxRow(runId, /* visibleFrom */ null, executionStartedEvent)));
            assert createdInboxEvents == 1;
        });

        return runId;
    }

    public void sendExternalEvent(final UUID workflowRunId, final String eventId, final WorkflowPayload content) {
        state.assertRunning();

        final var subjectBuilder = ExternalEventReceived.newBuilder()
                .setId(eventId);
        if (content != null) {
            subjectBuilder.setContent(content);
        }

        useJdbiTransaction(handle -> new WorkflowDao(handle).createInboxEvents(List.of(
                new NewWorkflowEventInboxRow(workflowRunId, null,
                        WorkflowEvent.newBuilder()
                                .setId(-1)
                                .setTimestamp(Timestamps.now())
                                .setExternalEventReceived(subjectBuilder.build())
                                .build()))));
    }

    List<WorkflowRunTask> pollWorkflowRunTasks(final String workflowName, final int limit) {
        return inJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final Map<UUID, PolledWorkflowRunRow> polledRunById =
                    dao.pollAndLockWorkflowRuns(this.instanceId, workflowName, Duration.ofMinutes(5), limit);
            if (polledRunById.isEmpty()) {
                return Collections.emptyList();
            }

            final Map<UUID, List<WorkflowEvent>> eventLogByRunId =
                    dao.getWorkflowEventLogs(polledRunById.keySet());

            final Map<UUID, List<WorkflowEvent>> inboxEventsByRunId =
                    dao.pollAndLockInboxEvents(this.instanceId, polledRunById.keySet());

            return polledRunById.values().stream()
                    .map(polledRun -> {
                        final List<WorkflowEvent> eventLog = eventLogByRunId.getOrDefault(
                                polledRun.id(), Collections.emptyList());
                        final List<WorkflowEvent> inboxEvents = inboxEventsByRunId.getOrDefault(
                                polledRun.id(), Collections.emptyList());

                        return new WorkflowRunTask(
                                polledRun.id(),
                                polledRun.workflowName(),
                                polledRun.workflowVersion(),
                                polledRun.priority(),
                                polledRun.argument(),
                                eventLog,
                                inboxEvents);
                    })
                    .toList();
        });
    }

    void abandonWorkflowRunTask(final WorkflowRunTask task) {
        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final int unlockedEvents = dao.unlockInboxEvents(this.instanceId, task.workflowRunId());
            assert unlockedEvents == task.inboxEvents().size();

            final int unlockedWorkflowRuns = dao.unlockWorkflowRun(this.instanceId, task.workflowRunId());
            assert unlockedWorkflowRuns == 1;
        });
    }

    void completeWorkflowRunTask(final WorkflowRun workflowRun) {
        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            dao.updateWorkflowRun(this.instanceId, new WorkflowRunRowUpdate(
                    workflowRun.workflowRunId(),
                    workflowRun.status(),
                    workflowRun.argument().orElse(null),
                    workflowRun.result().orElse(null),
                    workflowRun.failureDetails().orElse(null),
                    workflowRun.createdAt().orElse(null),
                    workflowRun.updatedAt().orElse(null),
                    workflowRun.completedAt().orElse(null)));

            int sequenceNumber = workflowRun.eventLog().size();
            final var newEventLogEntries = new ArrayList<NewWorkflowEventLogRow>(workflowRun.inboxEvents().size());
            for (final WorkflowEvent newEvent : workflowRun.inboxEvents()) {
                newEventLogEntries.add(new NewWorkflowEventLogRow(
                        workflowRun.workflowRunId(),
                        sequenceNumber++,
                        toInstant(newEvent.getTimestamp()),
                        newEvent));
            }
            dao.createWorkflowEventLogEntries(newEventLogEntries);

            final var newInboxEvents = new ArrayList<NewWorkflowEventInboxRow>(
                    workflowRun.pendingTimerFiredEvents().size() + workflowRun.pendingWorkflowMessages().size());
            for (final WorkflowEvent newEvent : workflowRun.pendingTimerFiredEvents()) {
                newInboxEvents.add(new NewWorkflowEventInboxRow(
                        workflowRun.workflowRunId(),
                        toInstant(newEvent.getTimerFired().getElapseAt()),
                        newEvent));
            }
            final var newWorkflowRuns = new ArrayList<NewWorkflowRunRow>();
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
            if (!newWorkflowRuns.isEmpty()) {
                final List<WorkflowRunRow> createdRuns = dao.createWorkflowRuns(newWorkflowRuns);
                assert createdRuns.size() == newWorkflowRuns.size();
            }
            final int createdOutboxEvents = dao.createInboxEvents(newInboxEvents);
            assert createdOutboxEvents == newInboxEvents.size();

            final var newActivityTasks = new ArrayList<NewActivityTaskRow>(
                    workflowRun.pendingActivityTaskScheduledEvents().size());
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
                                : null));
            }
            final int createdActivityTasks = dao.createActivityTasks(newActivityTasks);
            assert createdActivityTasks == newActivityTasks.size();

            dao.deleteLockedInboxEvents(this.instanceId, workflowRun.workflowRunId());
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

}
