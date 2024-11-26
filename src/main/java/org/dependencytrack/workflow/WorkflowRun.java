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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskScheduled;
import org.dependencytrack.proto.workflow.v1alpha1.ParentWorkflowRun;
import org.dependencytrack.proto.workflow.v1alpha1.RunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.RunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.SideEffectExecuted;
import org.dependencytrack.proto.workflow.v1alpha1.SubWorkflowRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.SubWorkflowRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.SubWorkflowRunScheduled;
import org.dependencytrack.proto.workflow.v1alpha1.TimerFired;
import org.dependencytrack.proto.workflow.v1alpha1.TimerScheduled;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus;
import org.dependencytrack.workflow.WorkflowCommand.CompleteExecutionCommand;
import org.dependencytrack.workflow.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleActivityCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleSubWorkflowCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleTimerCommand;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.SequencedCollection;
import java.util.UUID;

import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_PENDING;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_RUNNING;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_SUSPENDED;
import static org.dependencytrack.workflow.WorkflowEngine.toTimestamp;

public class WorkflowRun {

    private final UUID workflowRunId;
    private final String workflowName;
    private final int workflowVersion;
    private final List<WorkflowEvent> eventLog;
    private final List<WorkflowEvent> inboxEvents;
    private final List<WorkflowEvent> pendingActivityTaskScheduledEvents;
    private final List<WorkflowEvent> pendingTimerFiredEvents;
    private final List<WorkflowMessage> pendingWorkflowMessages;
    private WorkflowEvent startedEvent;
    private WorkflowEvent completedEvent;
    private boolean isSuspended;
    private WorkflowPayload argument;
    private WorkflowPayload result;
    private String failureDetails;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant completedAt;

    WorkflowRun(
            final UUID workflowRunId,
            final String workflowName,
            final int workflowVersion,
            final List<WorkflowEvent> eventLog) {
        this.workflowRunId = workflowRunId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.eventLog = new ArrayList<>();
        this.inboxEvents = new ArrayList<>();
        this.pendingActivityTaskScheduledEvents = new ArrayList<>();
        this.pendingTimerFiredEvents = new ArrayList<>();
        this.pendingWorkflowMessages = new ArrayList<>();

        for (final WorkflowEvent event : eventLog) {
            onEvent(event, /* isNew */ false);
        }
    }

    UUID workflowRunId() {
        return workflowRunId;
    }

    List<WorkflowEvent> eventLog() {
        return eventLog;
    }

    List<WorkflowEvent> inboxEvents() {
        return inboxEvents;
    }

    List<WorkflowEvent> pendingActivityTaskScheduledEvents() {
        return pendingActivityTaskScheduledEvents;
    }

    List<WorkflowEvent> pendingTimerFiredEvents() {
        return pendingTimerFiredEvents;
    }

    List<WorkflowMessage> pendingWorkflowMessages() {
        return pendingWorkflowMessages;
    }

    WorkflowRunStatus status() {
        if (startedEvent == null) {
            return WORKFLOW_RUN_STATUS_PENDING;
        } else if (isSuspended) {
            return WORKFLOW_RUN_STATUS_SUSPENDED;
        } else if (completedEvent != null) {
            return completedEvent.getRunCompleted().getStatus();
        }

        return WORKFLOW_RUN_STATUS_RUNNING;
    }

    Optional<WorkflowPayload> argument() {
        return Optional.ofNullable(argument);
    }

    Optional<WorkflowPayload> result() {
        return Optional.ofNullable(result);
    }

    Optional<String> failureDetails() {
        return Optional.ofNullable(failureDetails);
    }

    Optional<Instant> createdAt() {
        return Optional.ofNullable(createdAt);
    }

    Optional<Instant> updatedAt() {
        return Optional.ofNullable(updatedAt);
    }

    Optional<Instant> completedAt() {
        return Optional.ofNullable(completedAt);
    }

    void onEvent(final WorkflowEvent event) {
        onEvent(event, true);
    }

    private void onEvent(final WorkflowEvent event, final boolean isNew) {
        switch (event.getSubjectCase()) {
            case RUN_STARTED -> {
                startedEvent = event;
                argument = event.getRunStarted().hasArgument()
                        ? event.getRunStarted().getArgument()
                        : null;
                createdAt = WorkflowEngine.toInstant(event.getTimestamp());
            }
            case RUN_COMPLETED -> {
                if (completedEvent != null) {
                    throw new IllegalStateException("Duplicate complete events");
                }
                completedEvent = event;
                result = event.getRunCompleted().hasResult()
                        ? event.getRunCompleted().getResult()
                        : null;
                failureDetails = event.getRunCompleted().hasFailureDetails()
                        ? event.getRunCompleted().getFailureDetails()
                        : null;
                completedAt = WorkflowEngine.toInstant(event.getTimestamp());
            }
            case RUN_SUSPENDED -> isSuspended = true;
            case RUN_RESUMED -> isSuspended = false;
        }

        if (isNew) {
            inboxEvents.add(event);
        } else {
            eventLog.add(event);
        }

        updatedAt = WorkflowEngine.toInstant(event.getTimestamp());
    }

    void executeCommands(final SequencedCollection<WorkflowCommand> commands) {
        for (final WorkflowCommand command : commands) {
            executeCommand(command);
        }
    }

    private void executeCommand(final WorkflowCommand command) {
        switch (command) {
            case CompleteExecutionCommand completeCommand -> executeCompleteExecutionCommand(completeCommand);
            case RecordSideEffectResultCommand sideEffectCommand ->
                    executeRecordSideEffectResultCommand(sideEffectCommand);
            case ScheduleActivityCommand activityCommand -> executeScheduleActivityTaskCommand(activityCommand);
            case ScheduleSubWorkflowCommand subWorkflowCommand -> executeScheduleSubWorkflowCommand(subWorkflowCommand);
            case ScheduleTimerCommand timerCommand -> executeScheduleTimerCommand(timerCommand);
            default -> throw new IllegalStateException("Unexpected command: " + command);
        }
    }

    private void executeCompleteExecutionCommand(final CompleteExecutionCommand command) {
        if (startedEvent.getRunStarted().hasParentRun()) {
            final ParentWorkflowRun parentRun = startedEvent.getRunStarted().getParentRun();
            final var parentRunId = UUID.fromString(parentRun.getRunId());

            final var subWorkflowEventBuilder = WorkflowEvent.newBuilder()
                    .setId(-1)
                    .setTimestamp(Timestamps.now());
            if (command.status() == WORKFLOW_RUN_STATUS_COMPLETED) {
                final var subWorkflowCompletedBuilder = SubWorkflowRunCompleted.newBuilder()
                        .setRunScheduledEventId(parentRun.getSubWorkflowRunScheduledEventId());
                if (command.result() != null) {
                    subWorkflowCompletedBuilder.setResult(command.result());
                }
                subWorkflowEventBuilder.setSubWorkflowRunCompleted(
                        subWorkflowCompletedBuilder.build());
            } else if (command.status() == WORKFLOW_RUN_STATUS_FAILED) {
                final var subWorkflowFailedBuilder = SubWorkflowRunFailed.newBuilder()
                        .setRunScheduledEventId(parentRun.getSubWorkflowRunScheduledEventId());
                if (command.failureDetails() != null) {
                    subWorkflowFailedBuilder.setFailureDetails(command.failureDetails());
                }
                subWorkflowEventBuilder.setSubWorkflowRunFailed(
                        subWorkflowFailedBuilder.build());
            } else {
                throw new IllegalStateException("Unexpected command status: " + command.status());
            }

            pendingWorkflowMessages.add(new WorkflowMessage(parentRunId, subWorkflowEventBuilder.build()));
        }

        final var subjectBuilder = RunCompleted.newBuilder()
                .setStatus(command.status());
        if (command.result() != null) {
            subjectBuilder.setResult(command.result());
        }
        if (command.failureDetails() != null) {
            subjectBuilder.setFailureDetails(command.failureDetails());
        }

        onEvent(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setRunCompleted(subjectBuilder.build())
                .build(), /* isNew */ true);
    }

    private void executeRecordSideEffectResultCommand(final RecordSideEffectResultCommand command) {
        final var subjectBuilder = SideEffectExecuted.newBuilder()
                .setSideEffectEventId(command.eventId());
        if (command.result() != null) {
            subjectBuilder.setResult(command.result());
        }

        onEvent(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setSideEffectExecuted(subjectBuilder.build())
                .build());
    }

    private void executeScheduleActivityTaskCommand(final ScheduleActivityCommand command) {
        final var subjectBuilder = ActivityTaskScheduled.newBuilder()
                .setName(command.name())
                .setVersion(command.version());
        if (command.priority() != null) {
            subjectBuilder.setPriority(command.priority());
        }
        if (command.argument() != null) {
            subjectBuilder.setArgument(command.argument());
        }
        if (command.scheduleFor() != null) {
            subjectBuilder.setScheduledFor(toTimestamp(command.scheduleFor()));
        }

        final var taskScheduledEvent = WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setActivityTaskScheduled(subjectBuilder.build())
                .build();
        onEvent(taskScheduledEvent, /* isNew */ true);
        pendingActivityTaskScheduledEvents.add(taskScheduledEvent);
    }

    private void executeScheduleSubWorkflowCommand(final ScheduleSubWorkflowCommand command) {
        final var subWorkflowRunId = UUID.randomUUID();

        final var subWorkflowScheduledBuilder = SubWorkflowRunScheduled.newBuilder()
                .setRunId(subWorkflowRunId.toString())
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion());
        final var subWorkflowRunStartedBuilder = RunStarted.newBuilder()
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion())
                .setParentRun(ParentWorkflowRun.newBuilder()
                        .setSubWorkflowRunScheduledEventId(command.eventId())
                        .setRunId(this.workflowRunId.toString())
                        .setWorkflowName(this.workflowName)
                        .setWorkflowVersion(this.workflowVersion)
                        .build());
        if (command.priority() != null) {
            subWorkflowScheduledBuilder.setPriority(command.priority());
        }
        if (command.argument() != null) {
            subWorkflowScheduledBuilder.setArgument(command.argument());
            subWorkflowRunStartedBuilder.setArgument(command.argument());
        }

        onEvent(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setSubWorkflowRunScheduled(subWorkflowScheduledBuilder.build())
                .build(), /* isNew */ true);

        pendingWorkflowMessages.add(new WorkflowMessage(
                subWorkflowRunId,
                WorkflowEvent.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setRunStarted(subWorkflowRunStartedBuilder.build())
                        .build()));
    }

    private void executeScheduleTimerCommand(final ScheduleTimerCommand command) {
        onEvent(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setTimerScheduled(TimerScheduled.newBuilder()
                        .setElapseAt(toTimestamp(command.elapseAt()))
                        .build())
                .build(), /* isNew */ true);

        pendingTimerFiredEvents.add(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setTimerFired(TimerFired.newBuilder()
                        .setTimerScheduledEventId(command.eventId())
                        .setElapseAt(toTimestamp(command.elapseAt()))
                        .build())
                .build());
    }

}
