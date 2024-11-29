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
import io.github.resilience4j.core.IntervalFunction;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskFailed;
import org.dependencytrack.proto.workflow.v1alpha1.RunCancelled;
import org.dependencytrack.proto.workflow.v1alpha1.RunResumed;
import org.dependencytrack.proto.workflow.v1alpha1.RunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.RunSuspended;
import org.dependencytrack.proto.workflow.v1alpha1.SideEffectExecuted;
import org.dependencytrack.proto.workflow.v1alpha1.SubWorkflowRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.SubWorkflowRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.TimerFired;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.WorkflowCommand.CompleteRunCommand;
import org.dependencytrack.workflow.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleActivityCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleSubWorkflowCommand;
import org.dependencytrack.workflow.WorkflowCommand.ScheduleTimerCommand;
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
import java.util.function.Function;

public final class WorkflowRunContext<A, R> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowRunContext.class);

    private final UUID workflowRunId;
    private final String workflowName;
    private final int workflowVersion;
    private final Integer priority;
    private final A argument;
    private final WorkflowRunner<A, R> workflowRunner;
    private final PayloadConverter<R> resultConverter;
    private final List<WorkflowEvent> eventLog;
    private final List<WorkflowEvent> inboxEvents;
    private final List<WorkflowEvent> suspendedEvents;
    private final Map<Integer, WorkflowCommand> pendingCommandByEventId;
    private final Map<Integer, Awaitable<?>> pendingAwaitableByEventId;
    private final Map<String, Queue<Awaitable<?>>> pendingAwaitablesByExternalEventId;
    private final Map<String, Queue<WorkflowEvent>> bufferedExternalEvents;
    private int currentEventIndex;
    private int currentEventId;
    private Instant currentTime;
    private boolean isInSideEffect;
    private boolean isReplaying;
    private boolean isSuspended;
    private String customStatus;

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
        this.workflowRunner = workflowRunner;
        this.resultConverter = resultConverter;
        this.eventLog = eventLog;
        this.inboxEvents = inboxEvents;
        this.suspendedEvents = new ArrayList<>();
        this.pendingCommandByEventId = new HashMap<>();
        this.pendingAwaitableByEventId = new HashMap<>();
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
        return new ReplayAwareLogger(this, LoggerFactory.getLogger(workflowRunner.getClass()));
    }

    public <AA, AR> Awaitable<AR> callActivity(
            final String name,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy) {
        assertNotInSideEffect("Activities can not be called from within a side effect");

        return callActivityInternal(name, argument, argumentConverter, resultConverter, retryPolicy, /* attempt */ 1, /* delay */ null);
    }

    private <AA, AR> Awaitable<AR> callActivityInternal(
            final String name,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy,
            final int attempt,
            final Duration delay) {
        final IntervalFunction retryIntervalFunction = IntervalFunction.ofExponentialRandomBackoff(
                retryPolicy.initialDelay(), retryPolicy.multiplier(), retryPolicy.randomizationFactor(), retryPolicy.maxDelay());
        return new RetryingAwaitable<>(this, resultConverter,
                () -> callActivityInternalWithNoRetries(name, argument, argumentConverter, resultConverter, delay),
                exception -> {
                    if (retryPolicy.maxAttempts() > 0 && attempt + 1 > retryPolicy.maxAttempts()) {
                        logger().warn("Max retry attempts ({}) exceeded", retryPolicy.maxAttempts());
                        throw exception;
                    }

                    final Duration nextDelay = Duration.ofMillis(retryIntervalFunction.apply(attempt + 1));
                    logger().info("Scheduling retry attempt #{} in {}", attempt, nextDelay);

                    return callActivityInternal(name, argument, argumentConverter, resultConverter, retryPolicy, attempt + 1, nextDelay);
                });
    }

    private <AA, AR> Awaitable<AR> callActivityInternalWithNoRetries(
            final String name,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final Duration delay) {
        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new ScheduleActivityCommand(
                        eventId,
                        name,
                        /* version */ -1,
                        this.priority,
                        argumentConverter.convertToPayload(argument),
                        delay != null ? currentTime.plus(delay) : null));

        final var awaitable = new Awaitable<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    public <WA, WR> Awaitable<WR> callSubWorkflow(
            final String name,
            final int version,
            final WA argument,
            final PayloadConverter<WA> argumentConverter,
            final PayloadConverter<WR> resultConverter) {
        assertNotInSideEffect("Sub workflows can not be called from within a side effect");

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new ScheduleSubWorkflowCommand(
                eventId, name, version, this.priority, argumentConverter.convertToPayload(argument)));

        final var awaitable = new Awaitable<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    public Awaitable<Void> scheduleTimer(final Duration delay) {
        assertNotInSideEffect("Timers can not be scheduled from within a side effect");

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new ScheduleTimerCommand(eventId, currentTime.plus(delay)));

        final var awaitable = new Awaitable<>(this, new VoidPayloadConverter());
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    public void setStatus(final String status) {
        this.customStatus = status;
    }

    public <SA, SR> Awaitable<SR> sideEffect(
            final SA argument,
            final PayloadConverter<SR> resultConverter,
            final Function<SA, SR> sideEffectFunction) {
        assertNotInSideEffect("Nested side effects are not allowed");

        final int eventId = currentEventId++;

        final var awaitable = new Awaitable<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);

        if (!isReplaying) {
            try {
                isInSideEffect = true;
                final SR result = sideEffectFunction.apply(argument);
                final WorkflowPayload resultPayload = resultConverter.convertToPayload(result);
                pendingCommandByEventId.put(eventId, new RecordSideEffectResultCommand(
                        eventId, resultPayload));
                awaitable.complete(resultPayload);
            } catch (RuntimeException e) {
                awaitable.completeExceptionally(e);
            } finally {
                isInSideEffect = false;
            }
        }

        return awaitable;
    }

    public <ER> Awaitable<ER> waitForExternalEvent(
            final String externalEventId,
            final PayloadConverter<ER> resultConverter,
            final Duration timeout) {
        assertNotInSideEffect("Waiting for external events is not allowed from within a side effect");

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

    WorkflowRunResult runWorkflow() {
        try {
            WorkflowEvent currentEvent;
            while ((currentEvent = processNextEvent()) != null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Processed {}", currentEvent);
                }
            }
        } catch (WorkflowRunBlockedException e) {
            LOGGER.debug("Blocked", e);
        } catch (WorkflowRunCancelledException e) {
            cancel(e.getMessage());
        } catch (Exception e) {
            fail(e);
        }

        final List<WorkflowCommand> commands = !isSuspended
                ? List.copyOf(pendingCommandByEventId.values())
                : Collections.emptyList();

        return new WorkflowRunResult(commands, customStatus);
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
        if (isSuspended && !event.hasRunResumed() && !event.hasRunCancelled()) {
            if (event.hasRunSuspended()) {
                logger().warn("""
                    Encountered RunSuspended event at index {}, \
                    but run is already suspended. Ignoring.""", currentEventIndex);
                return;
            }

            suspendedEvents.add(event);
            return;
        }

        switch (event.getSubjectCase()) {
            case RUNNER_STARTED -> onRunnerStarted(event.getTimestamp());
            case RUN_STARTED -> onRunStarted(event.getRunStarted());
            case RUN_CANCELLED -> onRunCancelled(event.getRunCancelled());
            case RUN_SUSPENDED -> onRunSuspended(event.getRunSuspended());
            case RUN_RESUMED -> onRunResumed(event.getRunResumed());
            case ACTIVITY_TASK_SCHEDULED -> onActivityTaskScheduled(event.getId());
            case ACTIVITY_TASK_COMPLETED -> onActivityTaskCompleted(event.getActivityTaskCompleted());
            case ACTIVITY_TASK_FAILED -> onActivityTaskFailed(event.getActivityTaskFailed());
            case SUB_WORKFLOW_RUN_SCHEDULED -> onSubWorkflowRunScheduled(event.getId());
            case SUB_WORKFLOW_RUN_COMPLETED -> onSubWorkflowRunCompleted(event.getSubWorkflowRunCompleted());
            case SUB_WORKFLOW_RUN_FAILED -> onSubWorkflowRunFailed(event.getSubWorkflowRunFailed());
            case TIMER_SCHEDULED -> onTimerScheduled(event.getId());
            case TIMER_FIRED -> onTimerFired(event.getTimerFired());
            case SIDE_EFFECT_EXECUTED -> onSideEffectExecuted(event.getSideEffectExecuted());
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
        logger().debug("Started");

        final Optional<R> result;
        try {
            result = workflowRunner.run(this);
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new RuntimeException(e);
        }

        complete(result.orElse(null));
    }

    private void onRunCancelled(final RunCancelled runCancelled) {
        logger().debug("Cancelled with reason: {}", runCancelled.getReason());
        throw new WorkflowRunCancelledException(runCancelled.getReason());
    }

    private void onRunSuspended(final RunSuspended ignored) {
        logger().debug("Suspended");
        isSuspended = true;
    }

    private void onRunResumed(final RunResumed ignored) {
        if (!isSuspended) {
            logger().warn("""
                    Encountered RunResumed event at index {}, \
                    but run is not in suspended state. Ignoring.""", currentEventIndex);
            return;
        }

        logger().debug("Resumed");
        isSuspended = false;

        for (final WorkflowEvent event : suspendedEvents) {
            processEvent(event);
        }
    }

    private void onActivityTaskScheduled(final int eventId) {
        logger().debug("Activity task scheduled for event ID {}", eventId);

        final WorkflowCommand action = pendingCommandByEventId.get(eventId);
        if (action == null) {
            logger().warn("""
                    Encountered ActivityTaskScheduled event for event ID {}, \
                    but no pending action was found for it""", eventId);
            return;
        } else if (!(action instanceof ScheduleActivityCommand)) {
            logger().warn("""
                    Encountered ActivityTaskScheduled event for event ID {}, \
                    but the pending action for that number is of type {}\
                    """, eventId, action.getClass().getSimpleName());
            return;
        }

        pendingCommandByEventId.remove(eventId);
    }

    private void onActivityTaskCompleted(final ActivityTaskCompleted subject) {
        final int eventId = subject.getTaskScheduledEventId();
        logger().debug("Activity task completed for event ID {}", eventId);

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered ActivityTaskCompleted event for event ID %d, \
                    but no pending awaitable exists for it""".formatted(eventId));
        }

        awaitable.complete(subject.hasResult() ? subject.getResult() : null);
        pendingAwaitableByEventId.remove(eventId);
    }

    private void onActivityTaskFailed(final ActivityTaskFailed subject) {
        final int eventId = subject.getTaskScheduledEventId();
        logger().debug("Activity task failed for event ID {}", eventId);

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered ActivityTaskFailed event for event ID %d, \
                    but no pending awaitable exists for it""".formatted(eventId));
        }

        // TODO: Reconstruct exception
        awaitable.completeExceptionally(new RuntimeException(subject.getFailureDetails()));
        pendingAwaitableByEventId.remove(eventId);
    }

    private void onSubWorkflowRunScheduled(final int eventId) {
        logger().debug("Sub workflow run scheduled for event ID {}", eventId);

        final WorkflowCommand command = pendingCommandByEventId.get(eventId);
        if (command == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered SubWorkflowRunScheduled event for event ID %d, \
                    but no pending command was found for it""".formatted(eventId));
        } else if (!(command instanceof ScheduleSubWorkflowCommand)) {
            throw new NonDeterministicWorkflowException("""
                    Encountered SubWorkflowRunScheduled event for event ID %d, \
                    but the pending command for that number is of type %s\
                    """.formatted(eventId, command.getClass().getSimpleName()));
        }

        pendingCommandByEventId.remove(eventId);
    }

    private void onSubWorkflowRunCompleted(final SubWorkflowRunCompleted subject) {
        final int eventId = subject.getRunScheduledEventId();
        logger().debug("Sub workflow run failed for event ID {}", eventId);

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered SubWorkflowRunCompleted event for event ID %d, \
                    but no pending awaitable exists for it""".formatted(eventId));
        }

        awaitable.complete(subject.hasResult() ? subject.getResult() : null);
        pendingAwaitableByEventId.remove(eventId);
    }

    private void onSubWorkflowRunFailed(final SubWorkflowRunFailed subject) {
        final int eventId = subject.getRunScheduledEventId();
        logger().debug("Sub workflow run failed for event ID {}", eventId);

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered SubWorkflowRunFailed event for event ID %d, \
                    but no pending awaitable exists for it""".formatted(eventId));
        }

        // TODO: Reconstruct exception
        awaitable.completeExceptionally(new RuntimeException(subject.getFailureDetails()));
        pendingAwaitableByEventId.remove(eventId);
    }

    private void onTimerScheduled(final int eventId) {
        logger().debug("Timer created for event ID {}", eventId);

        final WorkflowCommand action = pendingCommandByEventId.get(eventId);
        if (action == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered TimerScheduled event for event ID %d, \
                    but no pending action was found for it""".formatted(eventId));
        } else if (!(action instanceof ScheduleTimerCommand)) {
            throw new NonDeterministicWorkflowException("""
                    Encountered TimerScheduled event for event ID %d, \
                    but the pending action for that number is of type %s\
                    """.formatted(eventId, action.getClass().getSimpleName()));
        }

        pendingCommandByEventId.remove(eventId);
    }

    private void onTimerFired(final TimerFired subject) {
        final int eventId = subject.getTimerScheduledEventId();
        logger().debug("Timer fired for event ID {}", eventId);

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered TimerFired event for event ID %d, \
                    but no pending awaitable was found for it""".formatted(eventId));
        }

        pendingAwaitableByEventId.remove(eventId);
        awaitable.complete(null);
    }

    private void onSideEffectExecuted(final SideEffectExecuted subject) {
        final int eventId = subject.getSideEffectEventId();
        logger().debug("Side effect executed for event ID {}", eventId);

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered SideEffectExecuted event for event ID %d, \
                    but no pending awaitable was found for it""".formatted(eventId));
        }

        pendingAwaitableByEventId.remove(eventId);
        awaitable.complete(subject.hasResult()
                ? subject.getResult()
                : null);
    }

    private void onExternalEventReceived(final WorkflowEvent event) {
        final String externalEventId = event.getExternalEventReceived().getId();
        logger().debug("External event received for ID {}", externalEventId);

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

    private void cancel(final String reason) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} cancelled", workflowName, workflowRunId);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.CANCELLED,
                        /* result */ null,
                        reason));

        isSuspended = false;
    }

    private void complete(final R result) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} completed with result {}", workflowName, workflowRunId, result);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.COMPLETED,
                        resultConverter.convertToPayload(result),
                        /* failureDetails */ null));
    }

    private void fail(final Throwable exception) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} failed", workflowName, workflowRunId, exception);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.FAILED,
                        /* result */ null,
                        ExceptionUtils.getMessage(exception)));
    }

    private void assertNotInSideEffect(final String message) {
        if (isInSideEffect) {
            throw new IllegalStateException(message);
        }
    }

}
