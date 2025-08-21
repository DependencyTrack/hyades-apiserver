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
import org.dependencytrack.proto.workflow.event.v1.ActivityRunCreated;
import org.dependencytrack.proto.workflow.event.v1.ChildRunCompleted;
import org.dependencytrack.proto.workflow.event.v1.ChildRunCreated;
import org.dependencytrack.proto.workflow.event.v1.ChildRunFailed;
import org.dependencytrack.proto.workflow.event.v1.Event;
import org.dependencytrack.proto.workflow.event.v1.RunCompleted;
import org.dependencytrack.proto.workflow.event.v1.RunCreated;
import org.dependencytrack.proto.workflow.event.v1.SideEffectExecuted;
import org.dependencytrack.proto.workflow.event.v1.TimerCreated;
import org.dependencytrack.proto.workflow.event.v1.TimerElapsed;
import org.dependencytrack.proto.workflow.failure.v1.Failure;
import org.dependencytrack.proto.workflow.payload.v1.Payload;
import org.dependencytrack.workflow.engine.WorkflowCommand.CompleteRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ContinueRunAsNewCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.CreateActivityRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.CreateChildRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.CreateTimerCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.UUID;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toTimestamp;

/**
 * State of a workflow run.
 * <p>
 * The state is event-sourced by applying {@link Event}s,
 * and modified via processing of {@link WorkflowCommand}s.
 * <p>
 * This merely implements a state machine and does not
 * perform any I/O or otherwise mutating operations.
 */
final class WorkflowRunState {

    private final UUID id;
    @Nullable private String workflowName;
    @Nullable Integer workflowVersion;
    @Nullable private String concurrencyGroupId;
    private final List<Event> eventHistory;
    private final List<Event> newEvents;
    private final List<Event> pendingActivityRunCreatedEvents;
    private final List<Event> pendingTimerElapsedEvents;
    private final List<WorkflowRunMessage> pendingMessages;
    @Nullable private Event createdEvent;
    @Nullable private Event startedEvent;
    @Nullable private Event completedEvent;
    @Nullable private Payload argument;
    @Nullable private Payload result;
    @Nullable private Failure failure;
    @Nullable private WorkflowRunStatus status;
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
            final List<Event> eventHistory) {
        this.id = id;
        this.eventHistory = new ArrayList<>(eventHistory.size());
        this.newEvents = new ArrayList<>();
        this.pendingActivityRunCreatedEvents = new ArrayList<>();
        this.pendingTimerElapsedEvents = new ArrayList<>();
        this.pendingMessages = new ArrayList<>();

        for (final Event event : eventHistory) {
            applyEvent(event, /* isNew */ false);
        }
    }

    UUID id() {
        return id;
    }

    @Nullable
    String workflowName() {
        return workflowName;
    }

    @Nullable
    Integer workflowVersion() {
        return workflowVersion;
    }

    @Nullable
    String concurrencyGroupId() {
        return concurrencyGroupId;
    }

    List<Event> eventHistory() {
        return eventHistory;
    }

    List<Event> newEvents() {
        return newEvents;
    }

    List<Event> pendingActivityRunCreatedEvents() {
        return pendingActivityRunCreatedEvents;
    }

    List<Event> pendingTimerElapsedEvents() {
        return pendingTimerElapsedEvents;
    }

    List<WorkflowRunMessage> pendingWorkflowMessages() {
        return pendingMessages;
    }

    @Nullable
    WorkflowRunStatus status() {
        return status;
    }

    @Nullable
    String customStatus() {
        return customStatus;
    }

    void setCustomStatus(@Nullable final String customStatus) {
        this.customStatus = customStatus;
    }

    @Nullable
    Integer priority() {
        return priority;
    }

    @Nullable
    Map<String, String> labels() {
        return labels;
    }

    @Nullable
    Payload argument() {
        return argument;
    }

    @Nullable
    Payload result() {
        return result;
    }

    @Nullable
    Failure failure() {
        return failure;
    }

    @Nullable
    Instant createdAt() {
        return createdAt;
    }

    @Nullable
    Instant updatedAt() {
        return updatedAt;
    }

    @Nullable
    Instant startedAt() {
        return startedAt;
    }

    @Nullable
    Instant completedAt() {
        return completedAt;
    }

    boolean continuedAsNew() {
        return continuedAsNew;
    }

    void applyEvent(final Event event) {
        applyEvent(event, /* isNew */ true);
    }

    private void applyEvent(final Event event, final boolean isNew) {
        switch (event.getSubjectCase()) {
            case RUN_CREATED -> {
                if (createdEvent != null) {
                    final String previousEventStr = DebugFormat.singleLine().toString(createdEvent);
                    final String nextEventStr = DebugFormat.singleLine().toString(event);

                    throw new IllegalStateException(
                            "%s/%s: Duplicate RunCreated event; Previous event is: %s; New event is: %s".formatted(
                                    this.workflowName, this.id, previousEventStr, nextEventStr));
                }
                workflowName = event.getRunCreated().getWorkflowName();
                workflowVersion = event.getRunCreated().getWorkflowVersion();
                concurrencyGroupId = event.getRunCreated().hasConcurrencyGroupId()
                        ? event.getRunCreated().getConcurrencyGroupId()
                        : null;
                setStatus(WorkflowRunStatus.CREATED);
                createdEvent = event;
                argument = event.getRunCreated().hasArgument()
                        ? event.getRunCreated().getArgument()
                        : null;
                priority = event.getRunCreated().hasPriority()
                        ? event.getRunCreated().getPriority()
                        : null;
                labels = event.getRunCreated().getLabelsCount() > 0
                        ? event.getRunCreated().getLabelsMap()
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
            newEvents.add(event);
        } else {
            eventHistory.add(event);
        }

        updatedAt = toInstant(event.getTimestamp());
    }

    void processCommands(final SequencedCollection<WorkflowCommand> commands) {
        for (final WorkflowCommand command : commands) {
            processCommand(command);
        }
    }

    private void processCommand(final WorkflowCommand command) {
        switch (command) {
            case CompleteRunCommand it -> processCompleteRunCommand(it);
            case ContinueRunAsNewCommand it -> processContinueAsNewCommand(it);
            case RecordSideEffectResultCommand it -> processRecordSideEffectResultCommand(it);
            case CreateActivityRunCommand it -> processCreateActivityRunCommand(it);
            case CreateChildRunCommand it -> processCreateChildRunCommand(it);
            case CreateTimerCommand it -> processCreateTimerCommand(it);
            default -> throw new IllegalStateException("Unexpected command: " + command);
        }
    }

    private void processCompleteRunCommand(final CompleteRunCommand command) {
        // If this is a sub-workflow run, ensure the parent run is informed about the outcome.
        if (createdEvent.getRunCreated().hasParentRun()) {
            final RunCreated.ParentRun parentRun = createdEvent.getRunCreated().getParentRun();
            final var parentRunId = UUID.fromString(parentRun.getRunId());

            final var childRunEventBuilder = Event.newBuilder()
                    .setId(-1)
                    .setTimestamp(Timestamps.now());
            if (command.status() == WorkflowRunStatus.COMPLETED) {
                final var childRunCompletedBuilder = ChildRunCompleted.newBuilder()
                        .setChildRunCreatedEventId(parentRun.getChildRunCreatedEventId());
                if (command.result() != null) {
                    childRunCompletedBuilder.setResult(command.result());
                }
                childRunEventBuilder.setChildRunCompleted(
                        childRunCompletedBuilder.build());
            } else if (command.status() == WorkflowRunStatus.CANCELED || command.status() == WorkflowRunStatus.FAILED) {
                final var childRunFailedBuilder = ChildRunFailed.newBuilder()
                        .setChildRunCreatedEventId(parentRun.getChildRunCreatedEventId());
                if (command.failure() != null) {
                    childRunFailedBuilder.setFailure(command.failure());
                }
                childRunEventBuilder.setChildRunFailed(
                        childRunFailedBuilder.build());
            } else {
                throw new IllegalStateException("Unexpected command status: " + command.status());
            }

            pendingMessages.add(new WorkflowRunMessage(parentRunId, childRunEventBuilder.build()));
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
        applyEvent(Event.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setRunCompleted(subjectBuilder.build())
                .build(), /* isNew */ true);
    }

    private void processContinueAsNewCommand(final ContinueRunAsNewCommand command) {
        final var newRunCreatedBuilder = RunCreated.newBuilder()
                .setWorkflowName(this.workflowName)
                .setWorkflowVersion(this.workflowVersion);
        if (command.argument() != null) {
            newRunCreatedBuilder.setArgument(command.argument());
        }
        if (this.concurrencyGroupId != null) {
            newRunCreatedBuilder.setConcurrencyGroupId(this.concurrencyGroupId);
        }
        if (this.priority != null) {
            newRunCreatedBuilder.setPriority(this.priority);
        }
        if (this.labels != null && !this.labels.isEmpty()) {
            newRunCreatedBuilder.putAllLabels(this.labels);
        }
        if (this.createdEvent.getRunCreated().hasParentRun()) {
            newRunCreatedBuilder.setParentRun(this.createdEvent.getRunCreated().getParentRun());
        }

        this.continuedAsNew = true;
        this.eventHistory.clear();
        this.newEvents.clear();
        this.pendingActivityRunCreatedEvents.clear();
        this.pendingTimerElapsedEvents.clear();
        this.pendingMessages.clear();
        this.pendingMessages.add(new WorkflowRunMessage(
                this.id,
                Event.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setRunCreated(newRunCreatedBuilder)
                        .build()));
    }

    private void processRecordSideEffectResultCommand(final RecordSideEffectResultCommand command) {
        final var subjectBuilder = SideEffectExecuted.newBuilder()
                .setSideEffectEventId(command.eventId())
                .setName(command.name());
        if (command.result() != null) {
            subjectBuilder.setResult(command.result());
        }

        applyEvent(Event.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setSideEffectExecuted(subjectBuilder.build())
                .build());
    }

    private void processCreateActivityRunCommand(final CreateActivityRunCommand command) {
        final var subjectBuilder = ActivityRunCreated.newBuilder()
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

        final var activityRunCreatedEvent = Event.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setActivityRunCreated(subjectBuilder.build())
                .build();
        applyEvent(activityRunCreatedEvent, /* isNew */ true);
        pendingActivityRunCreatedEvents.add(activityRunCreatedEvent);
    }

    private void processCreateChildRunCommand(final CreateChildRunCommand command) {
        final UUID childRunId = timeBasedEpochRandomGenerator().generate();

        final var childRunCreatedBuilder = ChildRunCreated.newBuilder()
                .setRunId(childRunId.toString())
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion());
        final var runCreatedBuilder = RunCreated.newBuilder()
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion())
                .setParentRun(RunCreated.ParentRun.newBuilder()
                        .setChildRunCreatedEventId(command.eventId())
                        .setRunId(this.id.toString())
                        .setWorkflowName(this.workflowName)
                        .setWorkflowVersion(this.workflowVersion)
                        .build());
        if (command.concurrencyGroupId() != null) {
            childRunCreatedBuilder.setConcurrencyGroupId(command.concurrencyGroupId());
            runCreatedBuilder.setConcurrencyGroupId(command.concurrencyGroupId());
        }
        if (command.priority() != null) {
            childRunCreatedBuilder.setPriority(command.priority());
            runCreatedBuilder.setPriority(command.priority());
        }
        if (command.labels() != null && !command.labels().isEmpty()) {
            childRunCreatedBuilder.putAllLabels(command.labels());
            runCreatedBuilder.putAllLabels(command.labels());
        }
        if (command.argument() != null) {
            childRunCreatedBuilder.setArgument(command.argument());
            runCreatedBuilder.setArgument(command.argument());
        }

        applyEvent(Event.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setChildRunCreated(childRunCreatedBuilder.build())
                .build(), /* isNew */ true);

        pendingMessages.add(new WorkflowRunMessage(
                childRunId,
                Event.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setRunCreated(runCreatedBuilder.build())
                        .build()));
    }

    private void processCreateTimerCommand(final CreateTimerCommand command) {
        applyEvent(Event.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setTimerCreated(TimerCreated.newBuilder()
                        .setName(command.name())
                        .setElapseAt(toTimestamp(command.elapseAt()))
                        .build())
                .build(), /* isNew */ true);

        pendingTimerElapsedEvents.add(Event.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setTimerElapsed(TimerElapsed.newBuilder()
                        .setTimerCreatedEventId(command.eventId())
                        .setElapseAt(toTimestamp(command.elapseAt()))
                        .build())
                .build());
    }

    private void setStatus(final WorkflowRunStatus newStatus) {
        if (this.status == null || this.status.canTransitionTo(newStatus)) {
            this.status = newStatus;
            return;
        }

        throw new IllegalStateException(
                "Can not transition from state %s to %s".formatted(this.status, newStatus));
    }

}
