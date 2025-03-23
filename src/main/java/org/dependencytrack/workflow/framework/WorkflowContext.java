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
package org.dependencytrack.workflow.framework;

import com.google.protobuf.DebugFormat;
import com.google.protobuf.Timestamp;
import org.dependencytrack.workflow.framework.ExecutorMetadataRegistry.ActivityMetadata;
import org.dependencytrack.workflow.framework.ExecutorMetadataRegistry.WorkflowMetadata;
import org.dependencytrack.workflow.framework.WorkflowCommand.CompleteRunCommand;
import org.dependencytrack.workflow.framework.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.workflow.framework.WorkflowCommand.ScheduleActivityCommand;
import org.dependencytrack.workflow.framework.WorkflowCommand.ScheduleSubWorkflowCommand;
import org.dependencytrack.workflow.framework.WorkflowCommand.ScheduleTimerCommand;
import org.dependencytrack.workflow.framework.failure.ActivityFailureException;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.dependencytrack.workflow.framework.failure.CancellationFailureException;
import org.dependencytrack.workflow.framework.failure.FailureConverter;
import org.dependencytrack.workflow.framework.failure.SideEffectFailureException;
import org.dependencytrack.workflow.framework.failure.SubWorkflowFailureException;
import org.dependencytrack.workflow.framework.payload.PayloadConverter;
import org.dependencytrack.workflow.framework.payload.VoidPayloadConverter;
import org.dependencytrack.workflow.framework.proto.v1alpha1.ActivityTaskCompleted;
import org.dependencytrack.workflow.framework.proto.v1alpha1.ActivityTaskFailed;
import org.dependencytrack.workflow.framework.proto.v1alpha1.ActivityTaskScheduled;
import org.dependencytrack.workflow.framework.proto.v1alpha1.RunCancelled;
import org.dependencytrack.workflow.framework.proto.v1alpha1.RunResumed;
import org.dependencytrack.workflow.framework.proto.v1alpha1.RunScheduled;
import org.dependencytrack.workflow.framework.proto.v1alpha1.RunStarted;
import org.dependencytrack.workflow.framework.proto.v1alpha1.RunSuspended;
import org.dependencytrack.workflow.framework.proto.v1alpha1.SideEffectExecuted;
import org.dependencytrack.workflow.framework.proto.v1alpha1.SubWorkflowRunCompleted;
import org.dependencytrack.workflow.framework.proto.v1alpha1.SubWorkflowRunFailed;
import org.dependencytrack.workflow.framework.proto.v1alpha1.SubWorkflowRunScheduled;
import org.dependencytrack.workflow.framework.proto.v1alpha1.TimerElapsed;
import org.dependencytrack.workflow.framework.proto.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.framework.proto.v1alpha1.WorkflowPayload;
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

import static java.util.Objects.requireNonNull;

/**
 * Context available to {@link WorkflowExecutor}s.
 *
 * @param <A> Type of the workflow's argument.
 * @param <R> Type of the workflow's result.
 */
public final class WorkflowContext<A, R> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowContext.class);

    private final UUID runId;
    private final String workflowName;
    private final int workflowVersion;
    private final Integer priority;
    private final Map<String, String> labels;
    private final ExecutorMetadataRegistry executorMetadataRegistry;
    private final WorkflowExecutor<A, R> workflowExecutor;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;
    private final List<WorkflowEvent> journal;
    private final List<WorkflowEvent> inbox;
    private final List<WorkflowEvent> suspendedEvents;
    private final Map<Integer, WorkflowEvent> eventByEventId;
    private final Map<Integer, WorkflowCommand> pendingCommandByEventId;
    private final Map<Integer, Awaitable<?>> pendingAwaitableByEventId;
    private final Map<String, Queue<Awaitable<?>>> pendingAwaitablesByExternalEventId;
    private final Map<String, Queue<WorkflowEvent>> bufferedExternalEvents;
    private int currentEventIndex;
    private int currentEventId;
    private Instant currentTime;
    private A argument;
    private boolean isInSideEffect;
    private boolean isReplaying;
    private boolean isSuspended;
    private String customStatus;

    WorkflowContext(
            final UUID runId,
            final String workflowName,
            final int workflowVersion,
            final Integer priority,
            final Map<String, String> labels,
            final ExecutorMetadataRegistry executorMetadataRegistry,
            final WorkflowExecutor<A, R> workflowExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final List<WorkflowEvent> journal,
            final List<WorkflowEvent> inbox) {
        this.runId = runId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.priority = priority;
        this.labels = labels;
        this.executorMetadataRegistry = executorMetadataRegistry;
        this.workflowExecutor = workflowExecutor;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
        this.journal = journal;
        this.inbox = inbox;
        this.suspendedEvents = new ArrayList<>();
        this.eventByEventId = new HashMap<>();
        this.pendingCommandByEventId = new HashMap<>();
        this.pendingAwaitableByEventId = new HashMap<>();
        this.pendingAwaitablesByExternalEventId = new HashMap<>();
        this.bufferedExternalEvents = new HashMap<>();
    }

    public UUID runId() {
        return runId;
    }

    public String workflowName() {
        return workflowName;
    }

    public int workflowVersion() {
        return workflowVersion;
    }

    public Map<String, String> labels() {
        return labels;
    }

    public Optional<A> argument() {
        return Optional.ofNullable(argument);
    }

    /**
     * @return The current, deterministic time within the workflow execution.
     */
    public Instant currentTime() {
        return currentTime;
    }

    /**
     * @return Whether the workflow is currently replaying past events.
     */
    public boolean isReplaying() {
        return isReplaying;
    }

    /**
     * @return A {@link Logger} to be used for logging within the workflow execution.
     * The {@link Logger} omits log events if the workflow is currently replaying past events,
     * avoiding redundant log emission.
     * @see #isReplaying()
     */
    public Logger logger() {
        return new ReplayAwareLogger(this, LoggerFactory.getLogger(workflowExecutor.getClass()));
    }

    public <AA, AR> ActivityClient<AA, AR> activityClient(final Class<? extends ActivityExecutor<AA, AR>> activityClass) {
        final ActivityMetadata<AA, AR> activityMetadata = executorMetadataRegistry.getActivityMetadata(activityClass);
        return new ActivityClient<>(
                this,
                activityMetadata.name(),
                activityMetadata.argumentConverter(),
                activityMetadata.resultConverter());
    }

    public <WA, WR> WorkflowClient<WA, WR> workflowClient(final Class<? extends WorkflowExecutor<WA, WR>> workflowClass) {
        final WorkflowMetadata<WA, WR> workflowMetadata = executorMetadataRegistry.getWorkflowMetadata(workflowClass);
        return new WorkflowClient<>(
                this,
                workflowMetadata.name(),
                workflowMetadata.version(),
                workflowMetadata.argumentConverter(),
                workflowMetadata.resultConverter());
    }

    <AA, AR> Awaitable<AR> callActivity(
            final String name,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy) {
        assertNotInSideEffect("Activities can not be called from within a side effect");

        return callActivityInternal(
                name,
                argument,
                argumentConverter,
                resultConverter,
                retryPolicy,
                /* attempt */ 1,
                /* delay */ null);
    }

    private <AA, AR> Awaitable<AR> callActivityInternal(
            final String name,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy,
            final int attempt,
            final Duration delay) {
        final Awaitable<AR> initialAwaitable = callActivityInternalWithNoRetries(
                name, argument, argumentConverter, resultConverter, delay);
        return new RetryingAwaitable<>(
                this,
                resultConverter,
                initialAwaitable,
                exception -> {
                    if (exception instanceof final ActivityFailureException activityException
                        && activityException.getCause() instanceof final ApplicationFailureException applicationException
                        && applicationException.isTerminal()) {
                        throw exception;
                    } else if (retryPolicy.maxAttempts() > 0 && attempt + 1 > retryPolicy.maxAttempts()) {
                        logger().warn("Max retry attempts ({}) exceeded", retryPolicy.maxAttempts());
                        throw exception;
                    }

                    final Duration nextDelay = Duration.ofMillis(retryPolicy.asIntervalFunction().apply(attempt + 1));
                    logger().warn("Activity {} failed; Scheduling retry attempt #{} in {}", name, attempt, nextDelay, exception);

                    return callActivityInternal(
                            name,
                            argument,
                            argumentConverter,
                            resultConverter,
                            retryPolicy,
                            attempt + 1,
                            nextDelay);
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

    <WA, WR> Awaitable<WR> callSubWorkflow(
            final String name,
            final int version,
            final String concurrencyGroupId,
            final WA argument,
            final PayloadConverter<WA> argumentConverter,
            final PayloadConverter<WR> resultConverter) {
        assertNotInSideEffect("Sub workflows can not be called from within a side effect");

        final WorkflowPayload convertedArgument = argumentConverter.convertToPayload(argument);

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new ScheduleSubWorkflowCommand(
                eventId, name, version, concurrencyGroupId, this.priority, this.labels, convertedArgument));

        final var awaitable = new Awaitable<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    /**
     * Schedules a durable timer.
     *
     * @param name  Name of the timer. Purely descriptive to make it recognizable in the journal.
     * @param delay {@link Duration} for how far in the future the timer shall elapse.
     * @return An {@link Awaitable} for when the timer elapses.
     */
    public Awaitable<Void> scheduleTimer(final String name, final Duration delay) {
        assertNotInSideEffect("Timers can not be scheduled from within a side effect");

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new ScheduleTimerCommand(eventId, name, currentTime.plus(delay)));

        final var awaitable = new Awaitable<>(this, new VoidPayloadConverter());
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    /**
     * Sets a custom status for the workflow run.
     * <p>
     * Does not overwrite the runtime status of the workflow run ({@link WorkflowRunStatus}).
     * <p>
     * May be useful for workflows that are observed by end users, requiring more descriptive
     * and more granular statuses.
     *
     * @param status The status to set. May be {@code null} to reset the custom status.
     */
    public void setStatus(final String status) {
        this.customStatus = status;
    }

    /**
     * Execute a side effect and record its result in the journal.
     * <p>
     * Calling {@link Awaitable#await()} on the {@link Awaitable} returned by this method
     * will throw an {@link SideEffectFailureException} if the side effect failed.
     *
     * @param name               Name of the side effect. Purely descriptive to make it recognizable in the journal.
     * @param argument           Argument to pass to {@code sideEffectFunction}.
     * @param resultConverter    {@link PayloadConverter} to use for the side effect's result.
     * @param sideEffectFunction The side effect to execute.
     * @param <SA>               Type of the side effect's argument.
     * @param <SR>               Type of the side effect's result.
     * @return An {@link Awaitable} wrapping the side effect's result, if any.
     */
    public <SA, SR> Awaitable<SR> sideEffect(
            final String name,
            final SA argument,
            final PayloadConverter<SR> resultConverter,
            final Function<SA, SR> sideEffectFunction) {
        assertNotInSideEffect("Nested side effects are not allowed");
        requireNonNull(name, "name must not be null");
        requireNonNull(sideEffectFunction, "sideEffectFunction must not be null");

        final int eventId = currentEventId++;

        final var awaitable = new Awaitable<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);

        if (!isReplaying) {
            try {
                isInSideEffect = true;
                final SR result = sideEffectFunction.apply(argument);
                final WorkflowPayload resultPayload = resultConverter.convertToPayload(result);
                pendingCommandByEventId.put(eventId, new RecordSideEffectResultCommand(
                        name, eventId, resultPayload));
                awaitable.complete(resultPayload);
            } catch (RuntimeException e) {
                awaitable.completeExceptionally(new SideEffectFailureException(name, e));
            } finally {
                isInSideEffect = false;
            }
        }

        return awaitable;
    }

    /**
     * Wait for an external event.
     * <p>
     * Calling {@link Awaitable#await()} on the {@link Awaitable} returned by this method
     * will throw a {@link CancellationFailureException} if the event is not received before
     * {@code timeout} elapses.
     *
     * @param externalEventId ID of the external event.
     * @param resultConverter {@link PayloadConverter} for the external event's content.
     * @param timeout         {@link Duration} to wait at most for the external event to arrive.
     * @param <ER>            Type of the external event's content.
     * @return An {@link Awaitable} wrapping the external event's content, if any.
     * @see WorkflowEngine#sendExternalEvent(UUID, String, WorkflowPayload)
     */
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
            awaitable.cancel("Timed out while waiting for external event");
            return awaitable;
        }

        pendingAwaitablesByExternalEventId.compute(externalEventId, (ignored, awaitables) -> {
            if (awaitables == null) {
                return new LinkedList<>(List.of(awaitable));
            }

            awaitables.add(awaitable);
            return awaitables;
        });

        scheduleTimer("External event %s wait timeout".formatted(externalEventId), timeout).onComplete(ignored -> {
            awaitable.cancel("Timed out while waiting for external event");

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

    WorkflowRunExecutionResult execute() {
        try {
            WorkflowEvent currentEvent;
            while ((currentEvent = processNextEvent()) != null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Processed {}", DebugFormat.singleLine().toString(currentEvent));
                }
            }
        } catch (WorkflowRunBlockedException e) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Blocked", e);
            }
        } catch (WorkflowRunCancelledException e) {
            cancel(e.getMessage());
        } catch (Exception e) {
            fail(e);
        }

        final List<WorkflowCommand> commands = !isSuspended
                ? List.copyOf(pendingCommandByEventId.values())
                : Collections.emptyList();

        return new WorkflowRunExecutionResult(commands, customStatus);
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
        if (event.getId() >= 0) {
            eventByEventId.put(event.getId(), event);
        }

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
            case EXECUTION_STARTED -> onExecutionStarted(event.getTimestamp());
            case RUN_SCHEDULED -> onRunScheduled(event.getRunScheduled());
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
            case TIMER_ELAPSED -> onTimerElapsed(event.getTimerElapsed());
            case SIDE_EFFECT_EXECUTED -> onSideEffectExecuted(event.getSideEffectExecuted());
            case EXTERNAL_EVENT_RECEIVED -> onExternalEventReceived(event);
        }
    }

    private WorkflowEvent nextEvent() {
        if (currentEventIndex < journal.size()) {
            isReplaying = true;
            return journal.get(currentEventIndex++);
        } else if (currentEventIndex < (journal.size() + inbox.size())) {
            isReplaying = false;
            return inbox.get(currentEventIndex++ - journal.size());
        }

        return null;
    }

    private void onExecutionStarted(final Timestamp timestamp) {
        currentTime = WorkflowEngine.toInstant(timestamp);
    }

    private void onRunScheduled(final RunScheduled runScheduled) {
        logger().debug("Scheduled");

        if (runScheduled.hasArgument()) {
            this.argument = argumentConverter.convertFromPayload(runScheduled.getArgument());
        }
    }

    private void onRunStarted(final RunStarted ignored) {
        logger().debug("Started");

        final Optional<R> result;
        try {
            result = workflowExecutor.execute(this);
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
        final int scheduledEventId = subject.getTaskScheduledEventId();
        logger().debug("Activity task failed for event ID {}", scheduledEventId);

        final WorkflowEvent scheduledEvent = eventByEventId.get(scheduledEventId);
        if (scheduledEvent == null || !scheduledEvent.hasActivityTaskScheduled()) {
            throw new NonDeterministicWorkflowException(
                    "Expected event with ID %d to be of type %s, but got: %s".formatted(
                            scheduledEventId,
                            ActivityTaskScheduled.class.getSimpleName(),
                            scheduledEvent != null ?
                                    DebugFormat.singleLine().toString(scheduledEvent)
                                    : null));
        }

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(scheduledEventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered ActivityTaskFailed event for event ID %d, \
                    but no pending awaitable exists for it""".formatted(scheduledEventId));
        }

        final var exception = new ActivityFailureException(
                scheduledEvent.getActivityTaskScheduled().getName(),
                /* TODO: activityVersion */ -1,
                FailureConverter.toException(subject.getFailure()));

        awaitable.completeExceptionally(exception);
        pendingAwaitableByEventId.remove(scheduledEventId);
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
        final int scheduledEventId = subject.getRunScheduledEventId();
        logger().debug("Sub workflow run failed for event ID {}", scheduledEventId);

        final WorkflowEvent scheduledEvent = eventByEventId.get(scheduledEventId);
        if (scheduledEvent == null || !scheduledEvent.hasSubWorkflowRunScheduled()) {
            throw new NonDeterministicWorkflowException(
                    "Expected event with ID %d to be of type %s, but got: %s".formatted(
                            scheduledEventId,
                            SubWorkflowRunScheduled.class.getSimpleName(),
                            scheduledEvent != null ?
                                    DebugFormat.singleLine().toString(scheduledEvent)
                                    : null));
        }

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(scheduledEventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException(
                    "Encountered %s event for event ID %d, but no pending awaitable exists for it".formatted(
                            SubWorkflowRunFailed.class.getSimpleName(), scheduledEventId));
        }

        final var exception = new SubWorkflowFailureException(
                UUID.fromString(scheduledEvent.getSubWorkflowRunScheduled().getRunId()),
                scheduledEvent.getSubWorkflowRunScheduled().getWorkflowName(),
                scheduledEvent.getSubWorkflowRunScheduled().getWorkflowVersion(),
                FailureConverter.toException(subject.getFailure()));

        awaitable.completeExceptionally(exception);
        pendingAwaitableByEventId.remove(scheduledEventId);
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

    private void onTimerElapsed(final TimerElapsed subject) {
        final int eventId = subject.getTimerScheduledEventId();
        logger().debug("Timer elapsed for event ID {}", eventId);

        final Awaitable<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered TimerElapsed event for event ID %d, \
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
            logger().debug("Workflow run {}/{} cancelled", workflowName, runId);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.CANCELLED,
                        customStatus,
                        /* result */ null,
                        FailureConverter.toFailure(new CancellationFailureException(reason))));

        isSuspended = false;
    }

    private void complete(final R result) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} completed with result {}", workflowName, runId, result);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.COMPLETED,
                        customStatus,
                        resultConverter.convertToPayload(result),
                        /* failure */ null));
    }

    private void fail(final Throwable exception) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} failed", workflowName, runId, exception);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.FAILED,
                        customStatus,
                        /* result */ null,
                        FailureConverter.toFailure(exception)));
    }

    private void assertNotInSideEffect(final String message) {
        if (isInSideEffect) {
            throw new IllegalStateException(message);
        }
    }

}
