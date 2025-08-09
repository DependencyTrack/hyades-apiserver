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
import com.google.protobuf.Timestamp;
import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.proto.workflow.api.v1.ActivityTaskCompleted;
import org.dependencytrack.proto.workflow.api.v1.ActivityTaskFailed;
import org.dependencytrack.proto.workflow.api.v1.ActivityTaskScheduled;
import org.dependencytrack.proto.workflow.api.v1.ChildRunCompleted;
import org.dependencytrack.proto.workflow.api.v1.ChildRunFailed;
import org.dependencytrack.proto.workflow.api.v1.ChildRunScheduled;
import org.dependencytrack.proto.workflow.api.v1.RunCanceled;
import org.dependencytrack.proto.workflow.api.v1.RunResumed;
import org.dependencytrack.proto.workflow.api.v1.RunScheduled;
import org.dependencytrack.proto.workflow.api.v1.RunStarted;
import org.dependencytrack.proto.workflow.api.v1.RunSuspended;
import org.dependencytrack.proto.workflow.api.v1.SideEffectExecuted;
import org.dependencytrack.proto.workflow.api.v1.TimerElapsed;
import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.ActivityHandle;
import org.dependencytrack.workflow.api.Awaitable;
import org.dependencytrack.workflow.api.ContinueAsNewOptions;
import org.dependencytrack.workflow.api.RetryPolicy;
import org.dependencytrack.workflow.api.WorkflowContext;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.WorkflowHandle;
import org.dependencytrack.workflow.api.failure.ActivityFailureException;
import org.dependencytrack.workflow.api.failure.ApplicationFailureException;
import org.dependencytrack.workflow.api.failure.CancellationFailureException;
import org.dependencytrack.workflow.api.failure.ChildWorkflowFailureException;
import org.dependencytrack.workflow.api.failure.SideEffectFailureException;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.engine.MetadataRegistry.ActivityMetadata;
import org.dependencytrack.workflow.engine.MetadataRegistry.WorkflowMetadata;
import org.dependencytrack.workflow.engine.WorkflowCommand.CompleteRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ContinueRunAsNewCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ScheduleActivityCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ScheduleChildRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.ScheduleTimerCommand;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.jspecify.annotations.Nullable;
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
import java.util.Queue;
import java.util.UUID;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toInstant;

final class WorkflowContextImpl<A, R> implements WorkflowContext<A> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowContextImpl.class);

    private final UUID runId;
    private final String workflowName;
    private final int workflowVersion;
    @Nullable private final Integer priority;
    @Nullable private final Map<String, String> labels;
    private final MetadataRegistry metadataRegistry;
    private final WorkflowExecutor<A, R> workflowExecutor;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;
    private final List<WorkflowEvent> history;
    private final List<WorkflowEvent> inbox;
    private final List<WorkflowEvent> suspendedEvents;
    private final Map<Integer, WorkflowEvent> eventByEventId;
    private final Map<Integer, WorkflowCommand> pendingCommandByEventId;
    private final Map<Integer, AwaitableImpl<?>> pendingAwaitableByEventId;
    private final Map<String, Queue<AwaitableImpl<?>>> pendingAwaitablesByExternalEventId;
    private final Map<String, Queue<WorkflowEvent>> bufferedExternalEvents;
    private final Logger logger;
    private int currentEventIndex;
    private int currentEventId;
    @Nullable private Instant currentTime;
    @Nullable private A argument;
    private boolean isInSideEffect;
    private boolean isReplaying;
    private boolean isSuspended;
    @Nullable private String customStatus;

    WorkflowContextImpl(
            final UUID runId,
            final String workflowName,
            final int workflowVersion,
            @Nullable final Integer priority,
            @Nullable final Map<String, String> labels,
            final MetadataRegistry metadataRegistry,
            final WorkflowExecutor<A, R> workflowExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final List<WorkflowEvent> history,
            final List<WorkflowEvent> inbox) {
        this.runId = runId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.priority = priority;
        this.labels = labels;
        this.metadataRegistry = metadataRegistry;
        this.workflowExecutor = workflowExecutor;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
        this.history = history;
        this.inbox = inbox;
        this.suspendedEvents = new ArrayList<>();
        this.eventByEventId = new HashMap<>();
        this.pendingCommandByEventId = new HashMap<>();
        this.pendingAwaitableByEventId = new HashMap<>();
        this.pendingAwaitablesByExternalEventId = new HashMap<>();
        this.bufferedExternalEvents = new HashMap<>();
        this.logger = new ReplayAwareLogger(this, LoggerFactory.getLogger(workflowExecutor.getClass()));
    }

    @Override
    public UUID runId() {
        return runId;
    }

    @Override
    public String workflowName() {
        return workflowName;
    }

    @Override
    public int workflowVersion() {
        return workflowVersion;
    }

    @Override
    public Map<String, String> labels() {
        return requireNonNullElse(labels, Collections.emptyMap());
    }

    @Nullable
    @Override
    public A argument() {
        return argument;
    }

    @Override
    public Instant currentTime() {
        if (currentTime == null) {
            throw new IllegalStateException("currentTime was not initialized");
        }

        return currentTime;
    }

    @Override
    public boolean isReplaying() {
        return isReplaying;
    }

    @Override
    public Logger logger() {
        return logger;
    }

    @Override
    public <AA, AR> ActivityHandle<AA, AR> activity(
            final Class<? extends ActivityExecutor<AA, AR>> activityClass) {
        final ActivityMetadata<AA, AR> activityMetadata =
                metadataRegistry.getActivityMetadata(activityClass);
        return new ActivityHandleImpl<>(
                this,
                activityMetadata.name(),
                activityMetadata.argumentConverter(),
                activityMetadata.resultConverter());
    }

    @Override
    public <WA, WR> WorkflowHandle<WA, WR> workflow(
            final Class<? extends WorkflowExecutor<WA, WR>> workflowClass) {
        final WorkflowMetadata<WA, WR> workflowMetadata =
                metadataRegistry.getWorkflowMetadata(workflowClass);
        return new WorkflowHandleImpl<>(
                this,
                workflowMetadata.name(),
                workflowMetadata.version(),
                workflowMetadata.argumentConverter(),
                workflowMetadata.resultConverter());
    }

    <AA, AR> Awaitable<AR> callActivity(
            final String name,
            @Nullable final AA argument,
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

    private <AA, AR> AwaitableImpl<AR> callActivityInternal(
            final String name,
            @Nullable final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy,
            final int attempt,
            @Nullable final Duration delay) {
        final AwaitableImpl<AR> initialAwaitable = callActivityInternalWithNoRetries(
                name, argument, argumentConverter, resultConverter, delay);
        return new RetryingAwaitableImpl<>(
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

                    final Duration nextDelay = getRetryDelay(retryPolicy, attempt);
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

    private <AA, AR> AwaitableImpl<AR> callActivityInternalWithNoRetries(
            final String name,
            @Nullable final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            @Nullable final Duration delay) {
        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new ScheduleActivityCommand(
                        eventId,
                        name,
                        /* version */ -1,
                        this.priority,
                        argumentConverter.convertToPayload(argument),
                        delay != null ? currentTime.plus(delay) : null));

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    <WA, WR> Awaitable<WR> callChildWorkflow(
            final String name,
            final int version,
            @Nullable final String concurrencyGroupId,
            @Nullable final WA argument,
            final PayloadConverter<WA> argumentConverter,
            final PayloadConverter<WR> resultConverter) {
        assertNotInSideEffect("Child workflows can not be called from within a side effect");

        final WorkflowPayload convertedArgument = argumentConverter.convertToPayload(argument);

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new ScheduleChildRunCommand(
                eventId, name, version, concurrencyGroupId, this.priority, this.labels, convertedArgument));

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    @Override
    public Awaitable<Void> createTimer(final String name, final Duration delay) {
        return scheduleTimerInternal(name, delay);
    }

    private AwaitableImpl<Void> scheduleTimerInternal(final String name, final Duration delay) {
        assertNotInSideEffect("Timers can not be scheduled from within a side effect");

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new ScheduleTimerCommand(eventId, name, currentTime.plus(delay)));

        final var awaitable = new AwaitableImpl<>(this, voidConverter());
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    @Override
    public void setStatus(final String status) {
        this.customStatus = status;
    }

    @Override
    public <SA, SR> Awaitable<SR> executeSideEffect(
            final String name,
            @Nullable final SA argument,
            final PayloadConverter<SR> resultConverter,
            final Function<SA, SR> sideEffectFunction) {
        assertNotInSideEffect("Nested side effects are not allowed");
        requireNonNull(name, "name must not be null");
        requireNonNull(sideEffectFunction, "sideEffectFunction must not be null");

        final int eventId = currentEventId++;

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
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

    @Override
    public <ER> Awaitable<ER> waitForExternalEvent(
            final String externalEventId,
            final PayloadConverter<ER> resultConverter,
            final Duration timeout) {
        assertNotInSideEffect("Waiting for external events is not allowed from within a side effect");

        final var awaitable = new AwaitableImpl<>(this, resultConverter);

        final Queue<WorkflowEvent> bufferedEvents = bufferedExternalEvents.get(externalEventId);
        if (bufferedEvents != null && !bufferedEvents.isEmpty()) {
            final WorkflowEvent event = bufferedEvents.poll();
            awaitable.complete(event.getExternalEventReceived().hasPayload()
                    ? event.getExternalEventReceived().getPayload()
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

        scheduleTimerInternal("External event %s wait timeout".formatted(externalEventId), timeout).onComplete(ignored -> {
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

    @Override
    public void continueAsNew(final ContinueAsNewOptions<A> options) {
        assertNotInSideEffect("continueAsNew is not allowed from within a side effect");
        requireNonNull(options, "options must not be null");
        throw new WorkflowRunContinuedAsNewException(
                argumentConverter.convertToPayload(options.argument()));
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
        } catch (WorkflowRunCanceledException e) {
            cancel(e.getMessage());
        } catch (WorkflowRunContinuedAsNewException e) {
            continueAsNew(e.getArgument());
        } catch (Exception e) {
            fail(e);
        }

        final List<WorkflowCommand> commands = !isSuspended
                ? List.copyOf(pendingCommandByEventId.values())
                : Collections.emptyList();

        return new WorkflowRunExecutionResult(commands, customStatus);
    }

    @Nullable
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

        if (isSuspended && !event.hasRunResumed() && !event.hasRunCanceled()) {
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
            case RUN_CANCELED -> onRunCanceled(event.getRunCanceled());
            case RUN_SUSPENDED -> onRunSuspended(event.getRunSuspended());
            case RUN_RESUMED -> onRunResumed(event.getRunResumed());
            case ACTIVITY_TASK_SCHEDULED -> onActivityTaskScheduled(event.getId());
            case ACTIVITY_TASK_COMPLETED -> onActivityTaskCompleted(event.getActivityTaskCompleted());
            case ACTIVITY_TASK_FAILED -> onActivityTaskFailed(event.getActivityTaskFailed());
            case CHILD_RUN_SCHEDULED -> onChildRunScheduled(event.getId());
            case CHILD_RUN_COMPLETED -> onChildRunCompleted(event.getChildRunCompleted());
            case CHILD_RUN_FAILED -> onChildRunFailed(event.getChildRunFailed());
            case TIMER_SCHEDULED -> onTimerScheduled(event.getId());
            case TIMER_ELAPSED -> onTimerElapsed(event.getTimerElapsed());
            case SIDE_EFFECT_EXECUTED -> onSideEffectExecuted(event.getSideEffectExecuted());
            case EXTERNAL_EVENT_RECEIVED -> onExternalEventReceived(event);
        }
    }

    @Nullable
    private WorkflowEvent nextEvent() {
        if (currentEventIndex < history.size()) {
            isReplaying = true;
            return history.get(currentEventIndex++);
        } else if (currentEventIndex < (history.size() + inbox.size())) {
            isReplaying = false;
            return inbox.get(currentEventIndex++ - history.size());
        }

        return null;
    }

    private void onExecutionStarted(final Timestamp timestamp) {
        currentTime = toInstant(timestamp);
    }

    private void onRunScheduled(final RunScheduled runScheduled) {
        logger().debug("Scheduled");

        if (runScheduled.hasArgument()) {
            this.argument = argumentConverter.convertFromPayload(runScheduled.getArgument());
        }
    }

    private void onRunStarted(final RunStarted ignored) {
        logger().debug("Started");

        final R result;
        try {
            result = workflowExecutor.execute(this);
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new RuntimeException(e);
        }

        complete(result);
    }

    private void onRunCanceled(final RunCanceled runCanceled) {
        logger().debug("Canceled with reason: {}", runCanceled.getReason());
        throw new WorkflowRunCanceledException(runCanceled.getReason());
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

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(eventId);
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

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(scheduledEventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered ActivityTaskFailed event for event ID %d, \
                    but no pending awaitable exists for it""".formatted(scheduledEventId));
        }

        final var exception = new ActivityFailureException(
                scheduledEvent.getActivityTaskScheduled().getName(),
                FailureConverter.toException(subject.getFailure()));

        awaitable.completeExceptionally(exception);
        pendingAwaitableByEventId.remove(scheduledEventId);
    }

    private void onChildRunScheduled(final int eventId) {
        logger().debug("Sub workflow run scheduled for event ID {}", eventId);

        final WorkflowCommand command = pendingCommandByEventId.get(eventId);
        if (command == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered ChildRunScheduled event for event ID %d, \
                    but no pending command was found for it""".formatted(eventId));
        } else if (!(command instanceof ScheduleChildRunCommand)) {
            throw new NonDeterministicWorkflowException("""
                    Encountered ChildRunScheduled event for event ID %d, \
                    but the pending command for that number is of type %s\
                    """.formatted(eventId, command.getClass().getSimpleName()));
        }

        pendingCommandByEventId.remove(eventId);
    }

    private void onChildRunCompleted(final ChildRunCompleted subject) {
        final int eventId = subject.getRunScheduledEventId();
        logger().debug("Sub workflow run failed for event ID {}", eventId);

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException("""
                    Encountered ChildRunCompleted event for event ID %d, \
                    but no pending awaitable exists for it""".formatted(eventId));
        }

        awaitable.complete(subject.hasResult() ? subject.getResult() : null);
        pendingAwaitableByEventId.remove(eventId);
    }

    private void onChildRunFailed(final ChildRunFailed subject) {
        final int scheduledEventId = subject.getRunScheduledEventId();
        logger().debug("Sub workflow run failed for event ID {}", scheduledEventId);

        final WorkflowEvent scheduledEvent = eventByEventId.get(scheduledEventId);
        if (scheduledEvent == null || !scheduledEvent.hasChildRunScheduled()) {
            throw new NonDeterministicWorkflowException(
                    "Expected event with ID %d to be of type %s, but got: %s".formatted(
                            scheduledEventId,
                            ChildRunScheduled.class.getSimpleName(),
                            scheduledEvent != null ?
                                    DebugFormat.singleLine().toString(scheduledEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(scheduledEventId);
        if (awaitable == null) {
            throw new NonDeterministicWorkflowException(
                    "Encountered %s event for event ID %d, but no pending awaitable exists for it".formatted(
                            ChildRunFailed.class.getSimpleName(), scheduledEventId));
        }

        final var exception = new ChildWorkflowFailureException(
                UUID.fromString(scheduledEvent.getChildRunScheduled().getRunId()),
                scheduledEvent.getChildRunScheduled().getWorkflowName(),
                scheduledEvent.getChildRunScheduled().getWorkflowVersion(),
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

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(eventId);
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

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(eventId);
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

        final WorkflowPayload externalEventContent = event.getExternalEventReceived().hasPayload()
                ? event.getExternalEventReceived().getPayload()
                : null;

        final Queue<AwaitableImpl<?>> pendingAwaitables = pendingAwaitablesByExternalEventId.get(externalEventId);
        if (pendingAwaitables != null) {
            final AwaitableImpl<?> awaitable = pendingAwaitables.poll();
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
            logger().debug("Workflow run {}/{} canceled", workflowName, runId);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.CANCELED,
                        customStatus,
                        /* result */ null,
                        FailureConverter.toFailure(new CancellationFailureException(reason))));

        isSuspended = false;
    }

    private void complete(@Nullable final R result) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} completed with result {}", workflowName, runId, result);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.COMPLETED,
                        customStatus,
                        resultConverter.convertToPayload(result),
                        /* failure */ null));
    }

    private void continueAsNew(@Nullable final WorkflowPayload argument) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} continued as new with argument {}", workflowName, runId, argument);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
                new ContinueRunAsNewCommand(eventId, argument));
    }

    private void fail(final Throwable exception) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} failed", workflowName, runId, exception);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
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

    private static Duration getRetryDelay(final RetryPolicy retryPolicy, final int attempt) {
        final var intervalFunc = IntervalFunction.ofExponentialRandomBackoff(
                retryPolicy.initialDelay(),
                retryPolicy.multiplier(),
                retryPolicy.randomizationFactor(),
                retryPolicy.maxDelay());
        return Duration.ofMillis(intervalFunc.apply(attempt + 1));
    }

}
