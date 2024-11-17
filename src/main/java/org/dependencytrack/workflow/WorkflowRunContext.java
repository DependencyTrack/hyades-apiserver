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

import com.google.protobuf.Timestamp;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskFailed;
import org.dependencytrack.proto.workflow.v1alpha1.RunResumed;
import org.dependencytrack.proto.workflow.v1alpha1.RunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.RunSuspended;
import org.dependencytrack.proto.workflow.v1alpha1.RunTerminated;
import org.dependencytrack.proto.workflow.v1alpha1.SubWorkflowRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.SubWorkflowRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.TimerFired;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.WorkflowCommand.CompleteExecutionCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleTimerCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleActivityTaskCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleSubWorkflowCommand;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.dependencytrack.workflow.payload.VoidPayloadConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.UUID;

import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;

public final class WorkflowRunContext<A, R> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowRunContext.class);

    private final UUID workflowRunId;
    private final String workflowName;
    private final int workflowVersion;
    private final Integer priority;
    private final A argument;
    private final WorkflowRunner<A, R> executor;
    private final PayloadConverter<R> resultConverter;
    private final List<WorkflowEvent> eventLog;
    private final List<WorkflowEvent> inboxEvents;
    private final List<WorkflowEvent> suspendedEvents;
    private final Map<Integer, WorkflowCommand> pendingActionBySequenceId;
    private final Map<Integer, Awaitable<?>> pendingAwaitableBySequenceId;
    private final Map<String, Queue<Awaitable<?>>> pendingAwaitablesByExternalEventId;
    private final Map<String, Queue<WorkflowEvent>> bufferedExternalEvents;
    private int currentEventIndex;
    private int currentSequenceId;
    private Instant currentTime;
    private boolean isReplaying;
    private boolean isSuspended;

    WorkflowRunContext(
            final UUID workflowRunId,
            final String workflowName,
            final int workflowVersion,
            final Integer priority,
            final A argument,
            final WorkflowRunner<A, R> workflowRunner,
            final PayloadConverter<R> resultConverter,
            final List<WorkflowEvent> eventLog,
            final List<WorkflowEvent> inboxEvents) {
        this.workflowRunId = workflowRunId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.priority = priority;
        this.argument = argument;
        this.executor = workflowRunner;
        this.resultConverter = resultConverter;
        this.eventLog = eventLog;
        this.inboxEvents = inboxEvents;
        this.suspendedEvents = new ArrayList<>();
        this.pendingActionBySequenceId = new HashMap<>();
        this.pendingAwaitableBySequenceId = new HashMap<>();
        this.pendingAwaitablesByExternalEventId = new HashMap<>();
        this.bufferedExternalEvents = new HashMap<>();
    }

    public UUID workflowRunId() {
        return workflowRunId;
    }

    public String workflowName() {
        return workflowName;
    }

    public int workflowVersion() {
        return workflowVersion;
    }

    public Optional<A> argument() {
        return Optional.ofNullable(argument);
    }

    public boolean isReplaying() {
        return isReplaying;
    }

    public Logger logger() {
        return new WorkflowReplayAwareLogger(this, LoggerFactory.getLogger(executor.getClass()));
    }

    public <AA, AR> Awaitable<AR> callActivity(
            final String name,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter) {
        final int sequenceId = currentSequenceId++;
        pendingActionBySequenceId.put(sequenceId,
                new ScheduleActivityTaskCommand(
                        sequenceId,
                        name,
                        /* version */ -1,
                        this.priority,
                        argumentConverter.convertToPayload(argument)));

        final var awaitable = new Awaitable<>(this, resultConverter);
        pendingAwaitableBySequenceId.put(sequenceId, awaitable);
        return awaitable;
    }

    public <WA, WR> Awaitable<WR> callSubWorkflow(
            final String name,
            final int version,
            final WA argument,
            final PayloadConverter<WA> argumentConverter,
            final PayloadConverter<WR> resultConverter) {
        final int sequenceId = currentSequenceId++;
        pendingActionBySequenceId.put(sequenceId, new ScheduleSubWorkflowCommand(
                sequenceId, name, version, this.priority, argumentConverter.convertToPayload(argument)));

        final var awaitable = new Awaitable<>(this, resultConverter);
        pendingAwaitableBySequenceId.put(sequenceId, awaitable);
        return awaitable;
    }

    // TODO: callLocalActivity, run synchronously but persist result to log.

    public Awaitable<Void> scheduleTimer(final Duration delay) {
        final int sequenceId = currentSequenceId++;
        pendingActionBySequenceId.put(sequenceId, new ScheduleTimerCommand(sequenceId, currentTime.plus(delay)));

        final var awaitable = new Awaitable<>(this, new VoidPayloadConverter());
        pendingAwaitableBySequenceId.put(sequenceId, awaitable);
        return awaitable;
    }

    public <ER> Awaitable<ER> waitForExternalEvent(
            final String externalEventId,
            final PayloadConverter<ER> resultConverter,
            final Duration timeout) {
        final var awaitable = new Awaitable<>(this, resultConverter);

        final Queue<WorkflowEvent> bufferedEvents = bufferedExternalEvents.get(externalEventId);
        if (bufferedEvents != null && !bufferedEvents.isEmpty()) {
            final WorkflowEvent event = bufferedEvents.poll();
            awaitable.complete(event.getExternalEventReceived().hasContent()
                    ? event.getExternalEventReceived().getContent()
                    : null);
            return awaitable;
        }

        if (timeout.equals(Duration.ZERO)) {
            awaitable.cancel();
            return awaitable;
        }

        pendingAwaitablesByExternalEventId.compute(externalEventId, (ignored, awaitables) -> {
            if (awaitables == null) {
                return new LinkedList<>(List.of(awaitable));
            }

            awaitables.add(awaitable);
            return awaitables;
        });

        scheduleTimer(timeout).onComplete(ignored -> {
            awaitable.cancel();

            pendingAwaitablesByExternalEventId.computeIfPresent(externalEventId, (ignoredKey, awaitables) -> {
                awaitables.remove(awaitable);
                if (awaitables.isEmpty()) {
                    return null;
                }

                return awaitables;
            });
        });

        return awaitable;
    }

    List<WorkflowCommand> runWorkflow() {
        try {
            WorkflowEvent currentEvent;
            while ((currentEvent = processNextEvent()) != null) {
                LOGGER.debug("Processed " + currentEvent);
            }
        } catch (WorkflowRunBlockedException e) {
            LOGGER.debug("Blocked", e);
        } catch (Exception e) {
            fail(e);
        }

        return !isSuspended
                ? List.copyOf(pendingActionBySequenceId.values())
                : Collections.emptyList();
    }

    WorkflowEvent processNextEvent() {
        final WorkflowEvent event = nextEvent();
        if (event == null) {
            return null;
        }

        processEvent(event);
        return event;
    }

    private void processEvent(final WorkflowEvent event) {
        if (isSuspended && !event.hasRunResumed() && !event.hasRunTerminated()) {
            suspendedEvents.add(event);
            return;
        }

        switch (event.getSubjectCase()) {
            case RUNNER_STARTED -> onRunnerStarted(event.getTimestamp());
            case RUN_STARTED -> onRunStarted(event.getRunStarted());
            case RUN_SUSPENDED -> onRunSuspended(event.getRunSuspended());
            case RUN_RESUMED -> onRunResumed(event.getRunResumed());
            case RUN_TERMINATED -> onRunTerminated(event.getRunTerminated());
            case ACTIVITY_TASK_SCHEDULED -> onActivityTaskScheduled(event.getSequenceId());
            case ACTIVITY_TASK_COMPLETED -> onActivityTaskCompleted(event.getActivityTaskCompleted());
            case ACTIVITY_TASK_FAILED -> onActivityTaskFailed(event.getActivityTaskFailed());
            case SUB_WORKFLOW_RUN_SCHEDULED -> onSubWorkflowRunScheduled(event.getSequenceId());
            case SUB_WORKFLOW_RUN_COMPLETED -> onSubWorkflowRunCompleted(event.getSubWorkflowRunCompleted());
            case SUB_WORKFLOW_RUN_FAILED -> onSubWorkflowRunFailed(event.getSubWorkflowRunFailed());
            case TIMER_SCHEDULED -> onTimerScheduled(event.getSequenceId());
            case TIMER_FIRED -> onTimerFired(event.getTimerFired());
            case EXTERNAL_EVENT_RECEIVED -> onExternalEventReceived(event);
        }
    }

    private WorkflowEvent nextEvent() {
        if (currentEventIndex < eventLog.size()) {
            isReplaying = true;
            return eventLog.get(currentEventIndex++);
        } else if (currentEventIndex < (eventLog.size() + inboxEvents.size())) {
            isReplaying = false;
            return inboxEvents.get(currentEventIndex++ - eventLog.size());
        }

        return null;
    }

    private void onRunnerStarted(final Timestamp timestamp) {
        currentTime = WorkflowEngine.toInstant(timestamp);
    }

    private void onRunStarted(final RunStarted ignored) {
        LOGGER.debug("Started");

        final Optional<R> result;
        try {
            result = executor.run(this);
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new RuntimeException(e);
        }
        result.ifPresentOrElse(this::complete, () -> complete(null));
    }

    private void onRunSuspended(final RunSuspended ignored) {
        LOGGER.debug("Suspended");
        this.isSuspended = true;
    }

    private void onRunResumed(final RunResumed ignored) {
        LOGGER.debug("Resumed");
        isSuspended = false;

        for (final WorkflowEvent event : suspendedEvents) {
            processEvent(event);
        }
    }

    private void onRunTerminated(final RunTerminated ignored) {
        LOGGER.debug("Terminated");
    }

    private void onActivityTaskScheduled(final int eventSequenceNumber) {
        LOGGER.debug("Activity task scheduled for sequence ID {}", eventSequenceNumber);

        final WorkflowCommand action = pendingActionBySequenceId.get(eventSequenceNumber);
        if (action == null) {
            LOGGER.warn("""
                    Encountered TaskScheduled event for sequence ID {}, \
                    but no pending action was found for it""", eventSequenceNumber);
            return;
        } else if (!(action instanceof ScheduleTimerCommand)) {
            LOGGER.warn("""
                    Encountered TaskScheduled event for sequence ID {}, \
                    but the pending action for that number is of type {}\
                    """, eventSequenceNumber, action.getClass().getSimpleName());
            return;
        }

        pendingActionBySequenceId.remove(eventSequenceNumber);
    }

    private void onActivityTaskCompleted(final ActivityTaskCompleted subject) {
        final int sequenceId = subject.getTaskScheduledSequenceId();
        LOGGER.debug("Activity task completed for sequence ID {}", sequenceId);

        final Awaitable<?> awaitable = pendingAwaitableBySequenceId.get(sequenceId);
        if (awaitable == null) {
            LOGGER.warn("""
                    Encountered TaskCompleted event for sequence ID {}, \
                    but no pending awaitable exists for it""", sequenceId);
            return;
        }

        awaitable.complete(subject.hasResult() ? subject.getResult() : null);
        pendingAwaitableBySequenceId.remove(sequenceId);
    }

    private void onActivityTaskFailed(final ActivityTaskFailed subject) {
        final int sequenceId = subject.getTaskScheduledSequenceId();
        LOGGER.debug("Activity task failed for sequence ID {}", sequenceId);

        final Awaitable<?> awaitable = pendingAwaitableBySequenceId.get(sequenceId);
        if (awaitable == null) {
            LOGGER.warn("""
                    Encountered TaskFailed event for sequence ID {}, \
                    but no pending awaitable exists for it""", sequenceId);
            return;
        }

        // TODO: Reconstruct exception
        awaitable.completeExceptionally(new RuntimeException(subject.getFailureDetails()));
        pendingAwaitableBySequenceId.remove(sequenceId);
    }

    private void onSubWorkflowRunScheduled(final int sequenceId) {
        LOGGER.debug("Sub workflow run scheduled for sequence ID {}", sequenceId);

        final WorkflowCommand command = pendingActionBySequenceId.get(sequenceId);
        if (command == null) {
            LOGGER.warn("""
                    Encountered SubWorkflowRunScheduled event for sequence ID {}, \
                    but no pending command was found for it""", sequenceId);
            return;
        } else if (!(command instanceof ScheduleSubWorkflowCommand)) {
            LOGGER.warn("""
                    Encountered SubWorkflowRunScheduled event for sequence ID {}, \
                    but the pending command for that number is of type {}\
                    """, sequenceId, command.getClass().getSimpleName());
            return;
        }

        pendingActionBySequenceId.remove(sequenceId);
    }

    private void onSubWorkflowRunCompleted(final SubWorkflowRunCompleted subject) {
        final int sequenceId = subject.getRunScheduledSequenceId();
        LOGGER.debug("Sub workflow run failed for sequence ID {}", sequenceId);

        final Awaitable<?> awaitable = pendingAwaitableBySequenceId.get(sequenceId);
        if (awaitable == null) {
            LOGGER.warn("""
                    Encountered SubWorkflowRunCompleted event for sequence ID {}, \
                    but no pending awaitable exists for it""", sequenceId);
            return;
        }

        awaitable.complete(subject.hasResult() ? subject.getResult() : null);
        pendingAwaitableBySequenceId.remove(sequenceId);
    }

    private void onSubWorkflowRunFailed(final SubWorkflowRunFailed subject) {
        final int sequenceId = subject.getRunScheduledSequenceId();
        LOGGER.debug("Sub workflow run failed for sequence ID {}", sequenceId);

        final Awaitable<?> awaitable = pendingAwaitableBySequenceId.get(sequenceId);
        if (awaitable == null) {
            LOGGER.warn("""
                    Encountered SubWorkflowRunFailed event for sequence ID {}, \
                    but no pending awaitable exists for it""", sequenceId);
            return;
        }

        // TODO: Reconstruct exception
        awaitable.completeExceptionally(new RuntimeException(subject.getFailureDetails()));
        pendingAwaitableBySequenceId.remove(sequenceId);
    }

    private void onTimerScheduled(final int sequenceId) {
        LOGGER.debug("Timer created for sequence ID {}", sequenceId);

        final WorkflowCommand action = pendingActionBySequenceId.get(sequenceId);
        if (action == null) {
            LOGGER.warn("""
                    Encountered TimerCreated event for sequence ID {}, \
                    but no pending action was found for it""", sequenceId);
            return;
        } else if (!(action instanceof ScheduleTimerCommand)) {
            LOGGER.warn("""
                    Encountered TimerCreated event for sequence ID {}, \
                    but the pending action for that number is of type {}\
                    """, sequenceId, action.getClass().getSimpleName());
            return;
        }

        pendingActionBySequenceId.remove(sequenceId);
    }

    private void onTimerFired(final TimerFired subject) {
        final int sequenceId = subject.getTimerCreatedSequenceId();
        LOGGER.debug("Timer fired for sequence ID {}", sequenceId);

        final Awaitable<?> awaitable = pendingAwaitableBySequenceId.get(sequenceId);
        if (awaitable == null) {
            LOGGER.warn("""
                    Encountered TimerFired event for sequence ID {}, \
                    but no pending awaitable was found for it""", sequenceId);
            return;
        }

        pendingAwaitableBySequenceId.remove(sequenceId);
        awaitable.complete(null);
    }

    private void onExternalEventReceived(final WorkflowEvent event) {
        final String externalEventId = event.getExternalEventReceived().getId();
        LOGGER.debug("External event received for ID {}", externalEventId);

        final WorkflowPayload externalEventContent = event.getExternalEventReceived().hasContent()
                ? event.getExternalEventReceived().getContent()
                : null;

        final Queue<Awaitable<?>> pendingAwaitables = pendingAwaitablesByExternalEventId.get(externalEventId);
        if (pendingAwaitables != null) {
            final Awaitable<?> awaitable = pendingAwaitables.poll();
            if (awaitable != null) {
                awaitable.complete(externalEventContent);
            }
            if (pendingAwaitables.isEmpty()) {
                pendingAwaitablesByExternalEventId.remove(externalEventId);
            }

            return;
        }

        bufferedExternalEvents.compute(externalEventId, (ignored, awaitables) -> {
            if (awaitables == null) {
                return new LinkedList<>(List.of(event));
            }

            awaitables.add(event);
            return awaitables;
        });
    }

    private void complete(final R result) {
        final int sequenceId = currentSequenceId++;
        pendingActionBySequenceId.put(sequenceId,
                new CompleteExecutionCommand(
                        sequenceId,
                        WORKFLOW_RUN_STATUS_COMPLETED,
                        resultConverter.convertToPayload(result),
                        /* failureDetails */ null));
    }

    private void fail(final Throwable exception) {
        final int sequenceId = currentSequenceId++;
        pendingActionBySequenceId.put(sequenceId,
                new CompleteExecutionCommand(
                        sequenceId,
                        WORKFLOW_RUN_STATUS_FAILED,
                        /* result */ null,
                        ExceptionUtils.getMessage(exception)));
    }

}
