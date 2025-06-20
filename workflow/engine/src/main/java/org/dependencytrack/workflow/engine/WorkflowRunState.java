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

import com.google.protobuf.DebugFormat;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.workflow.api.v1.ActivityTaskScheduled;
import org.dependencytrack.proto.workflow.api.v1.ParentWorkflowRun;
import org.dependencytrack.proto.workflow.api.v1.RunCompleted;
import org.dependencytrack.proto.workflow.api.v1.RunScheduled;
import org.dependencytrack.proto.workflow.api.v1.SideEffectExecuted;
import org.dependencytrack.proto.workflow.api.v1.SubWorkflowRunCompleted;
import org.dependencytrack.proto.workflow.api.v1.SubWorkflowRunFailed;
import org.dependencytrack.proto.workflow.api.v1.SubWorkflowRunScheduled;
import org.dependencytrack.proto.workflow.api.v1.TimerElapsed;
import org.dependencytrack.proto.workflow.api.v1.TimerScheduled;
import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.proto.workflow.api.v1.WorkflowFailure;
import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.dependencytrack.workflow.engine.WorkflowCommand.CompleteRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ContinueRunAsNewCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ScheduleActivityCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ScheduleSubWorkflowCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ScheduleTimerCommand;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SequencedCollection;
import java.util.UUID;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toTimestamp;

/**
 * Runtime state of a workflow run.
 * <p>
 * The state is event-sourced by consuming {@link WorkflowEvent}s,
 * and modified via execution of {@link WorkflowCommand}s.
 */
final class WorkflowRunState {

    private final UUID id;
    private final String workflowName;
    private final int workflowVersion;
    @Nullable private final String concurrencyGroupId;
    private final List<WorkflowEvent> history;
    private final List<WorkflowEvent> inbox;
    private final List<WorkflowEvent> pendingActivityTaskScheduledEvents;
    private final List<WorkflowEvent> pendingTimerElapsedEvents;
    private final List<WorkflowRunMessage> pendingMessages;
    @Nullable private WorkflowEvent scheduledEvent;
    @Nullable private WorkflowEvent startedEvent;
    @Nullable private WorkflowEvent completedEvent;
    @Nullable private WorkflowPayload argument;
    @Nullable private WorkflowPayload result;
    @Nullable private WorkflowFailure failure;
    private WorkflowRunStatus status = WorkflowRunStatus.PENDING;
    @Nullable private String customStatus;
    @Nullable private Integer priority;
    @Nullable private Map<String, String> labels;
    @Nullable private Instant createdAt;
    @Nullable private Instant updatedAt;
    @Nullable private Instant startedAt;
    @Nullable private Instant completedAt;
    private boolean continuedAsNew;

    WorkflowRunState(
            final UUID id,
            final String workflowName,
            final int workflowVersion,
            @Nullable final String concurrencyGroupId,
            final List<WorkflowEvent> history) {
        this.id = id;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.concurrencyGroupId = concurrencyGroupId;
        this.history = new ArrayList<>();
        this.inbox = new ArrayList<>();
        this.pendingActivityTaskScheduledEvents = new ArrayList<>();
        this.pendingTimerElapsedEvents = new ArrayList<>();
        this.pendingMessages = new ArrayList<>();

        for (final WorkflowEvent event : history) {
            onEvent(event, /* isNew */ false);
        }
    }

    UUID id() {
        return id;
    }

    String workflowName() {
        return workflowName;
    }

    int workflowVersion() {
        return workflowVersion;
    }

    Optional<String> concurrencyGroupId() {
        return Optional.ofNullable(concurrencyGroupId);
    }

    List<WorkflowEvent> history() {
        return history;
    }

    List<WorkflowEvent> inbox() {
        return inbox;
    }

    List<WorkflowEvent> pendingActivityTaskScheduledEvents() {
        return pendingActivityTaskScheduledEvents;
    }

    List<WorkflowEvent> pendingTimerElapsedEvents() {
        return pendingTimerElapsedEvents;
    }

    List<WorkflowRunMessage> pendingWorkflowMessages() {
        return pendingMessages;
    }

    WorkflowRunStatus status() {
        return status;
    }

    Optional<String> customStatus() {
        return Optional.ofNullable(customStatus);
    }

    void setCustomStatus(final String customStatus) {
        this.customStatus = customStatus;
    }

    Optional<Integer> priority() {
        return Optional.ofNullable(priority);
    }

    Optional<Map<String, String>> labels() {
        return Optional.ofNullable(labels);
    }

    Optional<WorkflowPayload> argument() {
        return Optional.ofNullable(argument);
    }

    Optional<WorkflowPayload> result() {
        return Optional.ofNullable(result);
    }

    Optional<WorkflowFailure> failure() {
        return Optional.ofNullable(failure);
    }

    Optional<Instant> createdAt() {
        return Optional.ofNullable(createdAt);
    }

    Optional<Instant> updatedAt() {
        return Optional.ofNullable(updatedAt);
    }

    Optional<Instant> startedAt() {
        return Optional.ofNullable(startedAt);
    }

    Optional<Instant> completedAt() {
        return Optional.ofNullable(completedAt);
    }

    boolean continuedAsNew() {
        return continuedAsNew;
    }

    void onEvent(final WorkflowEvent event) {
        onEvent(event, true);
    }

    private void onEvent(final WorkflowEvent event, final boolean isNew) {
        switch (event.getSubjectCase()) {
            case RUN_SCHEDULED -> {
                if (scheduledEvent != null) {
                    final String previousEventStr = DebugFormat.singleLine().toString(scheduledEvent);
                    final String nextEventStr = DebugFormat.singleLine().toString(event);

                    throw new IllegalStateException(
                            "%s/%s: Duplicate RunScheduled event; Previous event is: %s; New event is: %s".formatted(
                                    this.workflowName, this.id, previousEventStr, nextEventStr));
                }
                scheduledEvent = event;
                argument = event.getRunScheduled().hasArgument()
                        ? event.getRunScheduled().getArgument()
                        : null;
                priority = event.getRunScheduled().hasPriority()
                        ? event.getRunScheduled().getPriority()
                        : null;
                labels = event.getRunScheduled().getLabelsCount() > 0
                        ? event.getRunScheduled().getLabelsMap()
                        : null;
                createdAt = toInstant(event.getTimestamp());
            }
            case RUN_STARTED -> {
                if (startedEvent != null) {
                    final String previousEventStr = DebugFormat.singleLine().toString(startedEvent);
                    final String nextEventStr = DebugFormat.singleLine().toString(event);

                    throw new IllegalStateException(
                            "%s/%s: Duplicate RunStarted event; Previous event is: %s; New event is: %s".formatted(
                                    this.workflowName, this.id, previousEventStr, nextEventStr));
                }
                startedEvent = event;
                setStatus(WorkflowRunStatus.RUNNING);
                startedAt = toInstant(event.getTimestamp());
            }
            case RUN_COMPLETED -> {
                if (completedEvent != null) {
                    final String previousEventStr = DebugFormat.singleLine().toString(completedEvent);
                    final String nextEventStr = DebugFormat.singleLine().toString(event);

                    throw new IllegalStateException(
                            "%s/%s: Duplicate RunCompleted event; Previous event is: %s; Next event is: %s".formatted(
                                    this.workflowName, this.id, previousEventStr, nextEventStr));
                }
                completedEvent = event;
                setStatus(WorkflowRunStatus.fromProto(completedEvent.getRunCompleted().getStatus()));
                customStatus = event.getRunCompleted().hasCustomStatus()
                        ? event.getRunCompleted().getCustomStatus()
                        : null;
                result = event.getRunCompleted().hasResult()
                        ? event.getRunCompleted().getResult()
                        : null;
                failure = event.getRunCompleted().hasFailure()
                        ? event.getRunCompleted().getFailure()
                        : null;
                completedAt = toInstant(event.getTimestamp());
            }
            case RUN_SUSPENDED -> setStatus(WorkflowRunStatus.SUSPENDED);
            case RUN_RESUMED -> setStatus(WorkflowRunStatus.RUNNING);
        }

        if (isNew) {
            inbox.add(event);
        } else {
            history.add(event);
        }

        updatedAt = toInstant(event.getTimestamp());
    }

    void executeCommands(final SequencedCollection<WorkflowCommand> commands) {
        for (final WorkflowCommand command : commands) {
            executeCommand(command);
        }
    }

    private void executeCommand(final WorkflowCommand command) {
        switch (command) {
            case CompleteRunCommand it -> executeCompleteRunCommand(it);
            case ContinueRunAsNewCommand it -> executeContinueAsNewCommand(it);
            case RecordSideEffectResultCommand it -> executeRecordSideEffectResultCommand(it);
            case ScheduleActivityCommand it -> executeScheduleActivityTaskCommand(it);
            case ScheduleSubWorkflowCommand it -> executeScheduleSubWorkflowCommand(it);
            case ScheduleTimerCommand it -> executeScheduleTimerCommand(it);
            default -> throw new IllegalStateException("Unexpected command: " + command);
        }
    }

    private void executeCompleteRunCommand(final CompleteRunCommand command) {
        // If this is a sub-workflow run, ensure the parent run is informed about the outcome.
        if (scheduledEvent.getRunScheduled().hasParentRun()) {
            final ParentWorkflowRun parentRun = scheduledEvent.getRunScheduled().getParentRun();
            final var parentRunId = UUID.fromString(parentRun.getRunId());

            final var subWorkflowEventBuilder = WorkflowEvent.newBuilder()
                    .setId(-1)
                    .setTimestamp(Timestamps.now());
            if (command.status() == WorkflowRunStatus.COMPLETED) {
                final var subWorkflowCompletedBuilder = SubWorkflowRunCompleted.newBuilder()
                        .setRunScheduledEventId(parentRun.getSubWorkflowRunScheduledEventId());
                if (command.result() != null) {
                    subWorkflowCompletedBuilder.setResult(command.result());
                }
                subWorkflowEventBuilder.setSubWorkflowRunCompleted(
                        subWorkflowCompletedBuilder.build());
            } else if (command.status() == WorkflowRunStatus.CANCELLED || command.status() == WorkflowRunStatus.FAILED) {
                final var subWorkflowFailedBuilder = SubWorkflowRunFailed.newBuilder()
                        .setRunScheduledEventId(parentRun.getSubWorkflowRunScheduledEventId());
                if (command.failure() != null) {
                    subWorkflowFailedBuilder.setFailure(command.failure());
                }
                subWorkflowEventBuilder.setSubWorkflowRunFailed(
                        subWorkflowFailedBuilder.build());
            } else {
                throw new IllegalStateException("Unexpected command status: " + command.status());
            }

            pendingMessages.add(new WorkflowRunMessage(parentRunId, subWorkflowEventBuilder.build()));
        }

        // Record completion of the run in the history.
        final var subjectBuilder = RunCompleted.newBuilder()
                .setStatus(command.status().toProto());
        if (command.customStatus() != null) {
            subjectBuilder.setCustomStatus(command.customStatus());
        }
        if (command.result() != null) {
            subjectBuilder.setResult(command.result());
        }
        if (command.failure() != null) {
            subjectBuilder.setFailure(command.failure());
        }
        onEvent(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setRunCompleted(subjectBuilder.build())
                .build(), /* isNew */ true);
    }

    private void executeContinueAsNewCommand(ContinueRunAsNewCommand command) {
        final var newRunScheduledBuilder = RunScheduled.newBuilder()
                .setWorkflowName(this.workflowName)
                .setWorkflowVersion(this.workflowVersion);
        if (command.argument() != null) {
            newRunScheduledBuilder.setArgument(command.argument());
        }
        if (this.concurrencyGroupId != null) {
            newRunScheduledBuilder.setConcurrencyGroupId(this.concurrencyGroupId);
        }
        if (this.priority != null) {
            newRunScheduledBuilder.setPriority(this.priority);
        }
        if (this.labels != null && !this.labels.isEmpty()) {
            newRunScheduledBuilder.putAllLabels(this.labels);
        }
        if (this.scheduledEvent.getRunScheduled().hasParentRun()) {
            newRunScheduledBuilder.setParentRun(this.scheduledEvent.getRunScheduled().getParentRun());
        }

        this.continuedAsNew = true;
        this.history.clear();
        this.inbox.clear();
        this.pendingActivityTaskScheduledEvents.clear();
        this.pendingTimerElapsedEvents.clear();
        this.pendingMessages.clear();
        this.pendingMessages.add(new WorkflowRunMessage(
                this.id,
                WorkflowEvent.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setRunScheduled(newRunScheduledBuilder)
                        .build()));
    }

    private void executeRecordSideEffectResultCommand(final RecordSideEffectResultCommand command) {
        final var subjectBuilder = SideEffectExecuted.newBuilder()
                .setSideEffectEventId(command.eventId())
                .setName(command.name());
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
        final UUID subWorkflowRunId = timeBasedEpochRandomGenerator().generate();

        final var subWorkflowScheduledBuilder = SubWorkflowRunScheduled.newBuilder()
                .setRunId(subWorkflowRunId.toString())
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion());
        final var runScheduledBuilder = RunScheduled.newBuilder()
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion())
                .setParentRun(ParentWorkflowRun.newBuilder()
                        .setSubWorkflowRunScheduledEventId(command.eventId())
                        .setRunId(this.id.toString())
                        .setWorkflowName(this.workflowName)
                        .setWorkflowVersion(this.workflowVersion)
                        .build());
        if (command.concurrencyGroupId() != null) {
            subWorkflowScheduledBuilder.setConcurrencyGroupId(command.concurrencyGroupId());
            runScheduledBuilder.setConcurrencyGroupId(command.concurrencyGroupId());
        }
        if (command.priority() != null) {
            subWorkflowScheduledBuilder.setPriority(command.priority());
            runScheduledBuilder.setPriority(command.priority());
        }
        if (command.labels() != null && !command.labels().isEmpty()) {
            subWorkflowScheduledBuilder.putAllLabels(command.labels());
            runScheduledBuilder.putAllLabels(command.labels());
        }
        if (command.argument() != null) {
            subWorkflowScheduledBuilder.setArgument(command.argument());
            runScheduledBuilder.setArgument(command.argument());
        }

        onEvent(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setSubWorkflowRunScheduled(subWorkflowScheduledBuilder.build())
                .build(), /* isNew */ true);

        pendingMessages.add(new WorkflowRunMessage(
                subWorkflowRunId,
                WorkflowEvent.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setRunScheduled(runScheduledBuilder.build())
                        .build()));
    }

    private void executeScheduleTimerCommand(final ScheduleTimerCommand command) {
        onEvent(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setTimerScheduled(TimerScheduled.newBuilder()
                        .setName(command.name())
                        .setElapseAt(toTimestamp(command.elapseAt()))
                        .build())
                .build(), /* isNew */ true);

        pendingTimerElapsedEvents.add(WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setTimerElapsed(TimerElapsed.newBuilder()
                        .setTimerScheduledEventId(command.eventId())
                        .setElapseAt(toTimestamp(command.elapseAt()))
                        .build())
                .build());
    }

    private void setStatus(final WorkflowRunStatus newStatus) {
        if (this.status.canTransitionTo(newStatus)) {
            this.status = newStatus;
            return;
        }

        throw new IllegalStateException(
                "Can not transition from state %s to %s".formatted(this.status, newStatus));
    }

}
