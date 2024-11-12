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
import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.dependencytrack.event.kafka.consumer.KafkaBatchConsumer;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityCompletedResumeCondition;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunQueued;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunRequested;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunQueued;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunRequested;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunSuspended;
import org.dependencytrack.workflow.model.ModelState;
import org.dependencytrack.workflow.model.WorkflowActivityRunTask;
import org.dependencytrack.workflow.model.WorkflowRun;
import org.dependencytrack.workflow.model.WorkflowRunStatus;
import org.dependencytrack.workflow.model.WorkflowRunTask;
import org.dependencytrack.workflow.model.WorkflowTask;
import org.dependencytrack.workflow.model.WorkflowTaskStatus;
import org.dependencytrack.workflow.persistence.NewWorkflowRunEventLogEntryRow;
import org.dependencytrack.workflow.persistence.NewWorkflowTaskRow;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.WorkflowRunRowUpdate;
import org.dependencytrack.workflow.persistence.WorkflowTaskRow;
import org.dependencytrack.workflow.persistence.WorkflowTaskRowUpdate;
import org.slf4j.MDC;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_ACTIVITY_RUN_ID;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_EVENT_TYPE;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_RUN_ID;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.workflow.WorkflowEngine.DEFAULT_TASK_RETRY_INTERVAL_FUNCTION;
import static org.dependencytrack.workflow.WorkflowEngine.DEFAULT_TASK_RETRY_MAX_ATTEMPTS;

final class WorkflowEventConsumer extends KafkaBatchConsumer<UUID, WorkflowEvent> {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEventConsumer.class);

    private final WorkflowEngine engine;

    WorkflowEventConsumer(
            final WorkflowEngine engine,
            final KafkaConsumer<UUID, WorkflowEvent> kafkaConsumer,
            final Duration batchLingerDuration,
            final int batchSize) {
        super(kafkaConsumer, batchLingerDuration, batchSize);
        this.engine = engine;
    }

    @Override
    protected boolean flushBatch(final List<ConsumerRecord<UUID, WorkflowEvent>> records) {
        // Prepare history entries for all events in this batch.
        // Ensure they're inserted in chronological order.
        final List<NewWorkflowRunEventLogEntryRow> logEntriesToCreate = records.stream()
                .map(ConsumerRecord::value)
                .map(WorkflowEventConsumer::convertToHistoryEntry)
                .collect(Collectors.toList());

        final var eventsToSend = new ArrayList<WorkflowEvent>();

        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            // Create log entries for all events first.
            // The result tells us which events are indeed new.
            //
            // TODO: We have a FK constraint between WORKFLOW_RUN and WORKFLOW_RUN_LOG.
            //  If we consume historical data here, the insert will fail and we won't be able
            //  to make progress. Probably need a preflight check to filter out records that
            //  have no corresponding workflow run (anymore).
            final Set<UUID> createdLogEntryEventIds =
                    dao.createWorkflowRunEventLogEntries(logEntriesToCreate);
            if (createdLogEntryEventIds.isEmpty()) {
                LOGGER.info("No log entries created");
                return;
            }

            final List<WorkflowEvent> actionableEvents = records.stream()
                    .map(ConsumerRecord::value)
                    .filter(event -> createdLogEntryEventIds.contains(UUID.fromString(event.getId())))
                    .sorted(Comparator.comparing(WorkflowEvent::getTimestamp, Timestamps::compare))
                    .toList();

            final Set<String> workflowRunIds = actionableEvents.stream()
                    .map(WorkflowEvent::getWorkflowRunId)
                    .collect(Collectors.toSet());

            final Set<String> taskIds = new HashSet<>();
            for (final WorkflowEvent event : actionableEvents) {
                switch (event.getSubjectCase()) {
                    case RUN_QUEUED -> taskIds.add(event.getRunQueued().getTaskId());
                    case RUN_STARTED -> taskIds.add(event.getRunStarted().getTaskId());
                    case RUN_SUSPENDED -> taskIds.add(event.getRunSuspended().getTaskId());
                    case RUN_RESUMED -> taskIds.add(event.getRunResumed().getTaskId());
                    case RUN_COMPLETED -> taskIds.add(event.getRunCompleted().getTaskId());
                    case RUN_FAILED -> taskIds.add(event.getRunFailed().getTaskId());
                    case ACTIVITY_RUN_QUEUED -> taskIds.add(event.getActivityRunQueued().getTaskId());
                    case ACTIVITY_RUN_STARTED -> {
                        if (!event.getActivityRunStarted().getIsLocal()) {
                            taskIds.add(event.getActivityRunStarted().getTaskId());
                        }
                    }
                    case ACTIVITY_RUN_COMPLETED -> {
                        if (!event.getActivityRunCompleted().getIsLocal()) {
                            taskIds.add(event.getActivityRunCompleted().getTaskId());
                            taskIds.add(event.getActivityRunCompleted().getInvokingTaskId());
                        }
                    }
                    case ACTIVITY_RUN_FAILED -> {
                        if (!event.getActivityRunFailed().getIsLocal()) {
                            taskIds.add(event.getActivityRunFailed().getTaskId());
                            taskIds.add(event.getActivityRunFailed().getInvokingTaskId());
                        }
                    }
                }
            }

            // Fetch workflow runs relevant to the actionable events.
            // TODO: Cache these? Since events are partitioned by run ID, the cache can be local.
            //  Need to invalidate entries in onPartitionsRevoked and onPartitionsLost though.
            final List<WorkflowRunRow> runRows = dao.getWorkflowRunsById(
                    workflowRunIds.stream().map(UUID::fromString).toList());
            final Map<UUID, WorkflowRun> runById = runRows.stream()
                    .map(WorkflowRun::new)
                    .collect(Collectors.toMap(WorkflowRun::id, Function.identity()));

            // Fetch workflow tasks relevant to the actionable events.
            final List<WorkflowTaskRow> taskRows = dao.getQueuedTasksById(
                    taskIds.stream().map(UUID::fromString).toList());
            final Map<UUID, WorkflowTask> taskById = taskRows.stream()
                    .map(queuedTask -> queuedTask.activityRunId() != null
                            ? new WorkflowActivityRunTask(queuedTask)
                            : new WorkflowRunTask(queuedTask))
                    .collect(Collectors.toMap(WorkflowTask::id, Function.identity()));

            for (final WorkflowEvent event : actionableEvents) {
                final UUID workflowRunId = UUID.fromString(event.getWorkflowRunId());
                final UUID activityRunId = WorkflowEngine.extractActivityRunId(event).orElse(null);
                final var eventTimestamp = Instant.ofEpochSecond(0L, Timestamps.toNanos(event.getTimestamp()));
                final var ctx = new EventProcessingContext(
                        dao, eventTimestamp, workflowRunId, runById, taskById, eventsToSend);

                try (var ignoredMdcRunId = MDC.putCloseable(MDC_WORKFLOW_RUN_ID, String.valueOf(workflowRunId.toString()));
                     var ignoredMdcActivityRunId = MDC.putCloseable(MDC_WORKFLOW_ACTIVITY_RUN_ID, String.valueOf(activityRunId));
                     var ignoredMdcEventType = MDC.putCloseable(MDC_WORKFLOW_EVENT_TYPE, event.getSubjectCase().name())) {
                    switch (event.getSubjectCase()) {
                        case RUN_REQUESTED -> onRunRequested(ctx, event.getRunRequested());
                        case RUN_STARTED -> onRunStarted(ctx, event.getRunStarted());
                        case RUN_COMPLETED -> onRunCompleted(ctx, event.getRunCompleted());
                        case RUN_FAILED -> onRunFailed(ctx, event.getRunFailed());
                        case RUN_SUSPENDED -> onRunSuspended(ctx, event.getRunSuspended());
                        case ACTIVITY_RUN_REQUESTED -> onActivityRunRequested(ctx, event.getActivityRunRequested());
                        case ACTIVITY_RUN_COMPLETED -> onActivityRunCompleted(ctx, event.getActivityRunCompleted());
                        case ACTIVITY_RUN_FAILED -> onActivityRunFailed(ctx, event.getActivityRunFailed());
                        case EXTERNAL_EVENT_RECEIVED -> onExternalEventReceived(ctx, event.getExternalEventReceived());
                    }
                }
            }

            final Map<ModelState, List<WorkflowRun>> runsByModelState = runById.values().stream()
                    .collect(Collectors.groupingBy(WorkflowRun::modelState));
            final Map<ModelState, List<WorkflowTask>> taskByModelState = taskById.values().stream()
                    .collect(Collectors.groupingBy(WorkflowTask::modelState));

            // Runs must exist already. If we try to create them here, we did something wrong.
            assert runsByModelState.get(ModelState.NEW) == null;

            final var runsToUpdate = new ArrayList<WorkflowRunRowUpdate>();
            for (final WorkflowRun run : runsByModelState.getOrDefault(ModelState.CHANGED, Collections.emptyList())) {
                runsToUpdate.add(new WorkflowRunRowUpdate(
                        run.id(),
                        run.status(),
                        run.result(),
                        run.failureDetails(),
                        run.startedAt(),
                        run.endedAt()));
            }

            final var tasksToEnqueue = new ArrayList<NewWorkflowTaskRow>();
            for (final WorkflowTask task : taskByModelState.getOrDefault(ModelState.NEW, Collections.emptyList())) {
                tasksToEnqueue.add(switch (task) {
                    case WorkflowRunTask runTask ->
                            new NewWorkflowTaskRow(runTask.id(), runTask.queue(), runTask.workflowRunId())
                                    .withPriority(runTask.priority())
                                    .withScheduledFor(runTask.scheduledFor())
                                    .withArgument(runTask.argument());
                    case WorkflowActivityRunTask runTask ->
                            new NewWorkflowTaskRow(runTask.id(), runTask.queue(), runTask.workflowRunId())
                                    .withPriority(runTask.priority())
                                    .withScheduledFor(runTask.scheduledFor())
                                    .withArgument(runTask.argument())
                                    .withActivityRun(
                                            runTask.activityRunId(),
                                            runTask.activityName(),
                                            runTask.activityInvocationId(),
                                            runTask.invokingTaskId());
                });
            }

            final var tasksToUpdate = new ArrayList<WorkflowTaskRowUpdate>();
            for (final WorkflowTask task : taskByModelState.getOrDefault(ModelState.CHANGED, Collections.emptyList())) {
                tasksToUpdate.add(new WorkflowTaskRowUpdate(
                        task.id(),
                        task.status(),
                        task.scheduledFor()));
            }

            final var tasksToDelete = new ArrayList<UUID>();
            for (final WorkflowTask task : taskByModelState.getOrDefault(ModelState.DELETED, Collections.emptyList())) {
                tasksToDelete.add(task.id());
            }

            if (LOGGER.isDebugEnabled()) {
                for (final WorkflowRun run : runsByModelState.getOrDefault(ModelState.UNCHANGED, Collections.emptyList())) {
                    LOGGER.debug("Workflow run unchanged: " + run.id());
                }
                for (final WorkflowTask task : taskByModelState.getOrDefault(ModelState.UNCHANGED, Collections.emptyList())) {
                    LOGGER.debug("Task unchanged: " + task.id());
                }
            }

            if (!runsToUpdate.isEmpty()) {
                final List<UUID> updatedRunIds = dao.updateAllRuns(runsToUpdate);
                assert updatedRunIds.size() == runsToUpdate.size();

                if (LOGGER.isDebugEnabled()) {
                    for (final UUID updatedRunId : updatedRunIds) {
                        LOGGER.debug("Updated workflow run: " + updatedRunId);
                    }
                }
            }

            if (!tasksToEnqueue.isEmpty()) {
                final List<UUID> createdTaskIds = dao.createAllTasks(tasksToEnqueue);
                assert createdTaskIds.size() == tasksToEnqueue.size();

                if (LOGGER.isDebugEnabled()) {
                    for (final UUID taskId : createdTaskIds) {
                        LOGGER.debug("Created task: " + taskId);
                    }
                }
            }

            if (!tasksToUpdate.isEmpty()) {
                final List<UUID> updatedTaskIds = dao.updateAllTasks(tasksToUpdate);
                assert updatedTaskIds.size() == tasksToUpdate.size();

                if (LOGGER.isDebugEnabled()) {
                    for (final UUID updatedTaskId : updatedTaskIds) {
                        LOGGER.debug("Updated task: " + updatedTaskId);
                    }
                }
            }

            if (!tasksToDelete.isEmpty()) {
                final List<UUID> deletedTaskIds = dao.deleteAllTasks(tasksToDelete);
                assert deletedTaskIds.size() == tasksToDelete.size();

                if (LOGGER.isDebugEnabled()) {
                    for (final UUID deletedTaskId : deletedTaskIds) {
                        LOGGER.debug("Deleted task: " + deletedTaskId);
                    }
                }
            }
        });

        // TODO: Write to outbox table instead to avoid dual writes?
        if (!eventsToSend.isEmpty()) {
            // Ensure records are dispatched in chronological order.
            eventsToSend.sort(Comparator.comparing(WorkflowEvent::getTimestamp, Timestamps::compare));
            engine.dispatchEvents(eventsToSend).join();
        }

        return true;
    }

    private static NewWorkflowRunEventLogEntryRow convertToHistoryEntry(final WorkflowEvent event) {
        final var workflowRunId = UUID.fromString(event.getWorkflowRunId());
        final var eventId = UUID.fromString(event.getId());
        final var eventTimestamp = Instant.ofEpochSecond(0L, Timestamps.toNanos(event.getTimestamp()));

        return switch (event.getSubjectCase()) {
            case RUN_REQUESTED, RUN_QUEUED, RUN_STARTED, RUN_SUSPENDED, RUN_RESUMED,
                 RUN_COMPLETED, RUN_FAILED, EXTERNAL_EVENT_RECEIVED -> new NewWorkflowRunEventLogEntryRow(
                    workflowRunId,
                    eventTimestamp,
                    eventId,
                    event.getSubjectCase(),
                    /* activityRunId */ null,
                    event);
            case ACTIVITY_RUN_REQUESTED -> new NewWorkflowRunEventLogEntryRow(
                    workflowRunId,
                    eventTimestamp,
                    eventId,
                    event.getSubjectCase(),
                    UUID.fromString(event.getActivityRunRequested().getRunId()),
                    event);
            case ACTIVITY_RUN_QUEUED -> new NewWorkflowRunEventLogEntryRow(
                    workflowRunId,
                    eventTimestamp,
                    eventId,
                    event.getSubjectCase(),
                    UUID.fromString(event.getActivityRunQueued().getRunId()),
                    event);
            case ACTIVITY_RUN_STARTED -> new NewWorkflowRunEventLogEntryRow(
                    workflowRunId,
                    eventTimestamp,
                    eventId,
                    event.getSubjectCase(),
                    UUID.fromString(event.getActivityRunStarted().getRunId()),
                    event);
            case ACTIVITY_RUN_COMPLETED -> new NewWorkflowRunEventLogEntryRow(
                    workflowRunId,
                    eventTimestamp,
                    eventId,
                    event.getSubjectCase(),
                    UUID.fromString(event.getActivityRunCompleted().getRunId()),
                    event);
            case ACTIVITY_RUN_FAILED -> new NewWorkflowRunEventLogEntryRow(
                    workflowRunId,
                    eventTimestamp,
                    eventId,
                    event.getSubjectCase(),
                    UUID.fromString(event.getActivityRunFailed().getRunId()),
                    event);
            case SUBJECT_NOT_SET -> throw new IllegalStateException("Subject not set");
        };
    }

    private record EventProcessingContext(
            WorkflowDao dao,
            Instant eventTimestamp,
            UUID workflowRunId,
            Map<UUID, WorkflowRun> runById,
            Map<UUID, WorkflowTask> taskById,
            List<WorkflowEvent> eventsToSend) {

        private WorkflowRun getRunById(final UUID runId) {
            return runById.get(runId);
        }

        private void enqueueTask(final WorkflowTask task) {
            final WorkflowTask exitingTask = taskById.putIfAbsent(task.id(), task);
            if (exitingTask != null) {
                throw new IllegalStateException("A task with ID %s already exists".formatted(task.id()));
            }
        }

        private WorkflowTask getTaskById(final String taskId) {
            // NB: Processing of certain events (i.e. EXTERNAL_EVENT_RECEIVED) can
            // necessitate accessing of tasks that are not directly referenced by any event.
            // Unless many EXTERNAL_EVENT_RECEIVED events are processed, this should be rare.
            return taskById.computeIfAbsent(UUID.fromString(taskId), taskIdUuid -> {
                LOGGER.debug("Loading task " + taskId);
                final List<WorkflowTaskRow> taskRows = dao.getQueuedTasksById(List.of(taskIdUuid));
                if (!taskRows.isEmpty()) {
                    final WorkflowTaskRow taskRow = taskRows.getFirst();
                    if (taskRow.activityRunId() == null) {
                        return new WorkflowRunTask(taskRow);
                    }

                    return new WorkflowActivityRunTask(taskRow);
                }

                return null;
            });
        }

        private void enqueueEvent(final WorkflowEvent event) {
            eventsToSend().add(event);
        }

        private boolean hasActivityCompleted(final String activityRunId) {
            return dao.hasActivityCompletionEventLog(workflowRunId, UUID.fromString(activityRunId), eventTimestamp);
        }

        private List<WorkflowEvent> getEventLog() {
            // TODO: Utilize some basic caching to make this less impactful.
            // TODO: Only return log entries that the current event should be able to see.
            //  i.e. processing the current event shouldn't be able to see in the future.
            LOGGER.debug("Loading event log for run " + workflowRunId);
            return dao.getWorkflowRunEventLog(workflowRunId);
        }

    }

    private void onRunRequested(
            final EventProcessingContext ctx,
            final WorkflowRunRequested subject) {
        final var now = Instant.now();

        LOGGER.debug("Enqueueing workflow run task");
        final var newTask = new WorkflowRunTask(ctx.workflowRunId(), "workflow-" + subject.getName());
        if (subject.hasPriority()) {
            newTask.setPriority(subject.getPriority());
        }
        newTask.setArgument(subject.hasArgument() ? subject.getArgument() : null);
        newTask.setCreatedAt(now);
        ctx.enqueueTask(newTask);

        final var executionQueuedBuilder = WorkflowRunQueued.newBuilder()
                .setTaskId(newTask.id().toString());
        if (subject.hasPriority()) {
            executionQueuedBuilder.setPriority(subject.getPriority());
        }
        if (subject.hasArgument()) {
            executionQueuedBuilder.setArgument(subject.getArgument());
        }

        LOGGER.debug("Enqueueing %s event".formatted(WorkflowEvent.SubjectCase.RUN_QUEUED));
        ctx.enqueueEvent(
                WorkflowEvent.newBuilder()
                        .setId(UUID.randomUUID().toString())
                        .setWorkflowRunId(ctx.workflowRunId().toString())
                        .setTimestamp(Timestamps.fromMillis(now.toEpochMilli()))
                        .setRunQueued(executionQueuedBuilder.build())
                        .build());
    }

    private void onRunStarted(
            final EventProcessingContext ctx,
            final WorkflowRunStarted ignored) {
        final WorkflowRun run = ctx.getRunById(ctx.workflowRunId());

        // When resuming from suspension, the run is already in running state.
        if (run.status() != WorkflowRunStatus.RUNNING) {
            LOGGER.debug("Starting workflow run");
            run.start(ctx.eventTimestamp());
        }
    }

    private void onRunCompleted(
            final EventProcessingContext ctx,
            final WorkflowRunCompleted subject) {
        LOGGER.debug("Completing workflow run task");
        final WorkflowTask task = ctx.getTaskById(subject.getTaskId());
        task.complete();

        LOGGER.debug("Completing workflow run");
        final WorkflowRun run = ctx.getRunById(ctx.workflowRunId());
        run.complete(ctx.eventTimestamp(), subject.hasResult() ? subject.getResult() : null);
    }

    private void onRunFailed(
            final EventProcessingContext ctx,
            final WorkflowRunFailed subject) {
        final Instant nextAttemptAt;
        if (!subject.getIsTerminalFailure()
            && subject.getAttempt() + 1 <= DEFAULT_TASK_RETRY_MAX_ATTEMPTS) {
            final long retryDelayMillis = DEFAULT_TASK_RETRY_INTERVAL_FUNCTION.apply(subject.getAttempt());
            nextAttemptAt = ctx.eventTimestamp().plusMillis(retryDelayMillis);
        } else {
            nextAttemptAt = null;
        }

        LOGGER.debug("Failing workflow run task");
        final WorkflowTask task = ctx.getTaskById(subject.getTaskId());
        task.fail(nextAttemptAt);

        if (task.status() == WorkflowTaskStatus.FAILED) {
            LOGGER.debug("Failing workflow run because task failure is not retryable");
            final WorkflowRun run = ctx.getRunById(ctx.workflowRunId());
            run.fail(ctx.eventTimestamp(), subject.getFailureDetails());
        }
    }

    private void onRunSuspended(
            final EventProcessingContext ctx,
            final WorkflowRunSuspended subject) {
        LOGGER.debug("Suspending workflow run task");
        final var task = (WorkflowRunTask) ctx.getTaskById(subject.getTaskId());
        task.suspend();

        if (subject.hasActivityCompletedResumeCondition()) {
            final WorkflowActivityCompletedResumeCondition condition =
                    subject.getActivityCompletedResumeCondition();
            if (ctx.hasActivityCompleted(condition.getRunId())) {
                LOGGER.debug("Resuming suspended workflow run task because the resume condition is already fulfilled");
                task.resume();
            }
        }
    }

    private void onActivityRunRequested(
            final EventProcessingContext ctx,
            final WorkflowActivityRunRequested subject) {
        final var activityRunId = UUID.fromString(subject.getRunId());
        final var invokingTaskId = UUID.fromString(subject.getInvokingTaskId());
        final String activityName = subject.getActivityName();
        final String invocationId = subject.getInvocationId();
        final WorkflowRun run = ctx.getRunById(ctx.workflowRunId());

        LOGGER.debug("Enqueuing activity run task");
        final var newTask = new WorkflowActivityRunTask(
                ctx.workflowRunId(),
                "activity-" + activityName,
                activityRunId,
                activityName,
                invocationId,
                invokingTaskId);
        newTask.setPriority(run.priority());
        newTask.setArgument(subject.hasArgument() ? subject.getArgument() : null);
        newTask.setCreatedAt(Instant.now());
        ctx.enqueueTask(newTask);

        final var subjectBuilder = WorkflowActivityRunQueued.newBuilder()
                .setTaskId(newTask.id().toString())
                .setRunId(activityRunId.toString())
                .setActivityName(activityName)
                .setInvocationId(invocationId)
                .setInvokingTaskId(invokingTaskId.toString());
        if (subject.hasArgument()) {
            subjectBuilder.setArgument(subject.getArgument());
        }

        LOGGER.debug("Enqueuing %s event".formatted(WorkflowEvent.SubjectCase.ACTIVITY_RUN_QUEUED));
        ctx.enqueueEvent(
                WorkflowEvent.newBuilder()
                        .setId(UUID.randomUUID().toString())
                        .setWorkflowRunId(ctx.workflowRunId().toString())
                        .setTimestamp(Timestamps.fromMillis(newTask.createdAt().toEpochMilli()))
                        .setActivityRunQueued(subjectBuilder.build())
                        .build());
    }

    private void onActivityRunCompleted(
            final EventProcessingContext ctx,
            final WorkflowActivityRunCompleted subject) {
        if (subject.getIsLocal()) {
            LOGGER.debug("Activity run is local; Nothing to do");
            return;
        }

        LOGGER.debug("Completing activity run task");
        final WorkflowTask task = ctx.getTaskById(subject.getTaskId());
        task.complete();

        final var invokingTask = (WorkflowRunTask) ctx.getTaskById(subject.getInvokingTaskId());
        if (invokingTask.status() == WorkflowTaskStatus.SUSPENDED) {
            LOGGER.debug("Resuming suspended workflow run task %s".formatted(invokingTask.id()));
            invokingTask.resume();
        }
    }

    private void onActivityRunFailed(
            final EventProcessingContext ctx,
            final WorkflowActivityRunFailed subject) {
        if (subject.getIsLocal()) {
            LOGGER.debug("Activity run is local; Nothing to do");
            return;
        }

        final Instant nextAttemptAt;
        if (!subject.getIsTerminalFailure()
            && subject.getAttempt() + 1 <= DEFAULT_TASK_RETRY_MAX_ATTEMPTS) {
            final long retryDelayMillis = DEFAULT_TASK_RETRY_INTERVAL_FUNCTION.apply(subject.getAttempt());
            nextAttemptAt = ctx.eventTimestamp().plusMillis(retryDelayMillis);
        } else {
            nextAttemptAt = null;
        }

        LOGGER.debug("Failing activity run task");
        final WorkflowTask task = ctx.getTaskById(subject.getTaskId());
        task.fail(nextAttemptAt);

        if (task.status() == WorkflowTaskStatus.FAILED) {
            final var invokingTask = (WorkflowRunTask) ctx.getTaskById(subject.getInvokingTaskId());
            if (invokingTask.status() == WorkflowTaskStatus.SUSPENDED) {
                LOGGER.debug("""
                        Resuming suspended workflow run task %s because the \
                        activity task failure is not retryable""".formatted(invokingTask.id()));
                invokingTask.resume();
            }
        }
    }

    private void onExternalEventReceived(
            final EventProcessingContext ctx,
            final ExternalEventReceived subject) {
        WorkflowRunSuspended runSuspendedEvent = null;
        for (final WorkflowEvent event : ctx.getEventLog()) {
            if (event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_SUSPENDED
                && event.getRunSuspended().hasExternalEventReceivedCondition()
                && subject.getId().equals(event.getRunSuspended().getExternalEventReceivedCondition().getExternalEventId())) {
                runSuspendedEvent = event.getRunSuspended();
                break;
            }

            // TODO: Verify the run wasn't resumed and suspended for another condition in the meantime.
        }

        if (runSuspendedEvent == null) {
            LOGGER.debug("No run suspended event found");
            return;
        }

        final var task = (WorkflowRunTask) ctx.getTaskById(runSuspendedEvent.getTaskId());
        if (task.status() == WorkflowTaskStatus.SUSPENDED) {
            LOGGER.debug("Resuming suspended workflow run task");
            task.resume();
        }
    }

}
