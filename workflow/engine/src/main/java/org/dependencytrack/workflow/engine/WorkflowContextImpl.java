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
import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.proto.workflow.event.v1.ActivityRunCompleted;
import org.dependencytrack.proto.workflow.event.v1.ActivityRunCreated;
import org.dependencytrack.proto.workflow.event.v1.ActivityRunFailed;
import org.dependencytrack.proto.workflow.event.v1.ChildRunCompleted;
import org.dependencytrack.proto.workflow.event.v1.ChildRunCreated;
import org.dependencytrack.proto.workflow.event.v1.ChildRunFailed;
import org.dependencytrack.proto.workflow.event.v1.Event;
import org.dependencytrack.proto.workflow.event.v1.RunCanceled;
import org.dependencytrack.proto.workflow.event.v1.RunCreated;
import org.dependencytrack.proto.workflow.event.v1.SideEffectExecuted;
import org.dependencytrack.proto.workflow.event.v1.TimerCreated;
import org.dependencytrack.proto.workflow.event.v1.TimerElapsed;
import org.dependencytrack.proto.workflow.payload.v1.Payload;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.ActivityHandle;
import org.dependencytrack.workflow.api.Awaitable;
import org.dependencytrack.workflow.api.ContinueAsNewOptions;
import org.dependencytrack.workflow.api.RetryPolicy;
import org.dependencytrack.workflow.api.WorkflowContext;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.WorkflowHandle;
import org.dependencytrack.workflow.api.WorkflowRunBlockedError;
import org.dependencytrack.workflow.api.WorkflowRunCanceledError;
import org.dependencytrack.workflow.api.WorkflowRunContinuedAsNewError;
import org.dependencytrack.workflow.api.WorkflowRunDeterminismError;
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
import org.dependencytrack.workflow.engine.WorkflowCommand.CreateActivityRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.CreateChildRunCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.CreateTimerCommand;
import org.dependencytrack.workflow.engine.WorkflowCommand.RecordSideEffectResultCommand;
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
import java.util.Objects;
import java.util.Queue;
import java.util.UUID;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.workflow.engine.support.ProtobufUtil.toTimestamp;

final class WorkflowContextImpl<A, R> implements WorkflowContext<A> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowContextImpl.class);

    private final UUID runId;
    private final String workflowName;
    private final int workflowVersion;
    private final @Nullable Integer priority;
    private final @Nullable Map<String, String> labels;
    private final MetadataRegistry metadataRegistry;
    private final WorkflowExecutor<A, R> workflowExecutor;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;
    private final List<Event> eventHistory;
    private final List<Event> newEvents;
    private final List<Event> suspendedEvents;
    private final Map<Integer, Event> eventById;
    private final Map<Integer, WorkflowCommand> pendingCommandByEventId;
    private final Map<Integer, AwaitableImpl<?>> pendingAwaitableByEventId;
    private final Map<String, Queue<AwaitableImpl<?>>> pendingAwaitablesByExternalEventId;
    private final Map<String, Queue<Event>> bufferedExternalEvents;
    private final Logger logger;
    private int currentEventIndex;
    private int currentEventId;
    private @Nullable Instant currentTime;
    private @Nullable A argument;
    private boolean isInSideEffect;
    private boolean isReplaying;
    private boolean isSuspended;
    private @Nullable String customStatus;

    WorkflowContextImpl(
            final UUID runId,
            final String workflowName,
            final int workflowVersion,
            final @Nullable Integer priority,
            final @Nullable Map<String, String> labels,
            final MetadataRegistry metadataRegistry,
            final WorkflowExecutor<A, R> workflowExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final List<Event> eventHistory,
            final List<Event> newEvents) {
        this.runId = runId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.priority = priority;
        this.labels = labels;
        this.metadataRegistry = metadataRegistry;
        this.workflowExecutor = workflowExecutor;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
        this.eventHistory = eventHistory;
        this.newEvents = newEvents;
        this.suspendedEvents = new ArrayList<>();
        this.eventById = new HashMap<>();
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
            final @Nullable AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy) {
        requireNotInSideEffect("Activities can not be called from within a side effect");

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
            final @Nullable AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy,
            final int attempt,
            final @Nullable Duration delay) {
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
            final @Nullable AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final @Nullable Duration delay) {
        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CreateActivityRunCommand(
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
            final @Nullable String concurrencyGroupId,
            final @Nullable WA argument,
            final PayloadConverter<WA> argumentConverter,
            final PayloadConverter<WR> resultConverter) {
        requireNotInSideEffect("Child workflows can not be called from within a side effect");

        final Payload convertedArgument = argumentConverter.convertToPayload(argument);

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new CreateChildRunCommand(
                eventId, name, version, concurrencyGroupId, this.priority, this.labels, convertedArgument));

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    @Override
    public Awaitable<Void> createTimer(final String name, final Duration delay) {
        return createTimerInternal(name, delay);
    }

    private AwaitableImpl<Void> createTimerInternal(final String name, final Duration delay) {
        requireNotInSideEffect("Timers can not be created from within a side effect");

        final int eventId = currentEventId++;
        final int elapsedEventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new CreateTimerCommand(
                eventId, elapsedEventId, name, currentTime.plus(delay)));

        final var awaitable = new AwaitableImpl<>(this, voidConverter());
        pendingAwaitableByEventId.put(elapsedEventId, awaitable);
        return awaitable;
    }

    @Override
    public void setStatus(final @Nullable String status) {
        this.customStatus = status;
    }

    @Override
    public <SA, SR> Awaitable<SR> executeSideEffect(
            final String name,
            final @Nullable SA argument,
            final PayloadConverter<SR> resultConverter,
            final Function<@Nullable SA, @Nullable SR> sideEffectFunction) {
        requireNotInSideEffect("Nested side effects are not allowed");
        requireNonNull(name, "name must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(sideEffectFunction, "sideEffectFunction must not be null");

        final int eventId = currentEventId++;

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);

        if (!isReplaying) {
            try {
                isInSideEffect = true;
                final SR result = sideEffectFunction.apply(argument);
                final Payload resultPayload = resultConverter.convertToPayload(result);
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
        requireNotInSideEffect("Waiting for external events is not allowed from within a side effect");

        final var awaitable = new AwaitableImpl<>(this, resultConverter);

        final Queue<Event> bufferedEvents = bufferedExternalEvents.get(externalEventId);
        if (bufferedEvents != null && !bufferedEvents.isEmpty()) {
            final Event event = bufferedEvents.poll();
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

        createTimerInternal("External event %s wait timeout".formatted(externalEventId), timeout).onComplete(ignored -> {
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
        requireNotInSideEffect("continueAsNew is not allowed from within a side effect");
        requireNonNull(options, "options must not be null");
        throw new WorkflowRunContinuedAsNewError(
                argumentConverter.convertToPayload(options.argument()));
    }

    WorkflowRunExecutionResult execute() {
        try {
            Event currentEvent;
            while ((currentEvent = processNextEvent()) != null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Processed {}", DebugFormat.singleLine().toString(currentEvent));
                }
            }
        } catch (WorkflowRunBlockedError e) {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Blocked");
            }
        } catch (WorkflowRunCanceledError e) {
            cancel(e.getMessage());
        } catch (WorkflowRunContinuedAsNewError e) {
            continueAsNew(e.getArgument());
        } catch (WorkflowRunDeterminismError | Exception e) {
            fail(e);
        }

        final List<WorkflowCommand> commands = !isSuspended
                ? List.copyOf(pendingCommandByEventId.values())
                : Collections.emptyList();

        return new WorkflowRunExecutionResult(commands, customStatus);
    }

    @Nullable
    Event processNextEvent() {
        final Event event = nextEvent();
        if (event == null) {
            return null;
        }

        processEvent(event);
        return event;
    }

    private void processEvent(final Event event) {
        if (event.getId() >= 0) {
            eventById.put(event.getId(), event);
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
            case EXECUTION_STARTED -> onExecutionStarted(event);
            case RUN_CREATED -> onRunCreated(event);
            case RUN_STARTED -> onRunStarted(event);
            case RUN_CANCELED -> onRunCanceled(event);
            case RUN_SUSPENDED -> onRunSuspended(event);
            case RUN_RESUMED -> onRunResumed(event);
            case ACTIVITY_RUN_CREATED -> onActivityRunCreated(event);
            case ACTIVITY_RUN_COMPLETED -> onActivityRunCompleted(event);
            case ACTIVITY_RUN_FAILED -> onActivityRunFailed(event);
            case CHILD_RUN_CREATED -> onChildRunCreated(event);
            case CHILD_RUN_COMPLETED -> onChildRunCompleted(event);
            case CHILD_RUN_FAILED -> onChildRunFailed(event);
            case TIMER_CREATED -> onTimerCreated(event);
            case TIMER_ELAPSED -> onTimerElapsed(event);
            case SIDE_EFFECT_EXECUTED -> onSideEffectExecuted(event);
            case EXTERNAL_EVENT_RECEIVED -> onExternalEventReceived(event);
        }
    }

    private @Nullable Event nextEvent() {
        if (currentEventIndex < eventHistory.size()) {
            isReplaying = true;
            return eventHistory.get(currentEventIndex++);
        } else if (currentEventIndex < (eventHistory.size() + newEvents.size())) {
            isReplaying = false;
            return newEvents.get(currentEventIndex++ - eventHistory.size());
        }

        return null;
    }

    private void onExecutionStarted(final Event event) {
        currentTime = toInstant(event.getTimestamp());
    }

    private void onRunCreated(final Event event) {
        final RunCreated eventSubject = event.getRunCreated();
        logger().debug("Created");

        if (eventSubject.hasArgument()) {
            this.argument = argumentConverter.convertFromPayload(eventSubject.getArgument());
        }
    }

    private void onRunStarted(final Event ignored) {
        logger().debug("Started");

        final R result;
        try {
            result = workflowExecutor.execute(this, this.argument);
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new RuntimeException(e);
        }

        complete(result);
    }

    private void onRunCanceled(final Event event) {
        final RunCanceled eventSubject = event.getRunCanceled();
        logger().debug("Canceled with reason: {}", eventSubject.getReason());
        throw new WorkflowRunCanceledError(eventSubject.getReason());
    }

    private void onRunSuspended(final Event ignored) {
        logger().debug("Suspended");
        isSuspended = true;
    }

    private void onRunResumed(final Event ignored) {
        if (!isSuspended) {
            logger().warn("""
                    Encountered RunResumed event at index {}, \
                    but run is not in suspended state. Ignoring.""", currentEventIndex);
            return;
        }

        logger().debug("Resumed");
        isSuspended = false;

        for (final Event event : suspendedEvents) {
            processEvent(event);
        }
    }

    private void onActivityRunCreated(final Event event) {
        logger().debug("Activity run created for event ID {}", event.getId());
        final ActivityRunCreated eventSubject = event.getActivityRunCreated();

        final WorkflowCommand command = pendingCommandByEventId.get(event.getId());
        if (command == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    command was found for it""".formatted(
                    ActivityRunCreated.class.getSimpleName(),
                    event.getId()));
        } else if (!(command instanceof final CreateActivityRunCommand concreteCommand)) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but the corresponding \
                    command is of type %s (expected %s)""".formatted(
                    ActivityRunCreated.class.getSimpleName(),
                    event.getId(),
                    command.getClass().getSimpleName(),
                    CreateActivityRunCommand.class.getSimpleName()));
        } else if (!Objects.equals(eventSubject.getName(), concreteCommand.name())
                || (eventSubject.hasPriority()
                && !Objects.equals(eventSubject.getPriority(), concreteCommand.priority()))
                || (eventSubject.hasArgument()
                && !Objects.equals(eventSubject.getArgument(), concreteCommand.argument()))) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but it does not match \
                    the corresponding %s: event=%s, command=%s""".formatted(
                    ActivityRunCreated.class.getSimpleName(),
                    event.getId(),
                    CreateActivityRunCommand.class.getSimpleName(),
                    DebugFormat.singleLine().toString(eventSubject),
                    concreteCommand));
        }

        pendingCommandByEventId.remove(event.getId());
    }

    private void onActivityRunCompleted(final Event event) {
        final ActivityRunCompleted eventSubject = event.getActivityRunCompleted();
        final int createdEventId = eventSubject.getActivityRunCreatedEventId();
        logger().debug("Activity task completed for event ID {}", createdEventId);

        final Event createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasActivityRunCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ActivityRunCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ActivityRunCompleted.class.getSimpleName(),
                    createdEventId));
        }

        awaitable.complete(eventSubject.hasResult() ? eventSubject.getResult() : null);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onActivityRunFailed(final Event event) {
        final ActivityRunFailed eventSubject = event.getActivityRunFailed();
        final int createdEventId = eventSubject.getActivityRunCreatedEventId();
        logger().debug("Activity task failed for event ID {}", createdEventId);

        final Event createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasActivityRunCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ActivityRunCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ActivityRunCompleted.class.getSimpleName(),
                    createdEventId));
        }

        final var exception = new ActivityFailureException(
                createdEvent.getActivityRunCreated().getName(),
                FailureConverter.toException(eventSubject.getFailure()));

        awaitable.completeExceptionally(exception);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onChildRunCreated(final Event event) {
        logger().debug("Child workflow run created for event ID {}", event.getId());
        final ChildRunCreated eventSubject = event.getChildRunCreated();

        final WorkflowCommand command = pendingCommandByEventId.get(event.getId());
        if (command == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    command was found for it""".formatted(
                    ChildRunCreated.class.getSimpleName(),
                    event.getId()));
        } else if (!(command instanceof final CreateChildRunCommand concreteCommand)) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but the corresponding \
                    command is of type %s (expected %s)""".formatted(
                    ChildRunCreated.class.getSimpleName(),
                    event.getId(),
                    command.getClass().getSimpleName(),
                    CreateChildRunCommand.class.getSimpleName()));
        } else if (!Objects.equals(eventSubject.getWorkflowName(), concreteCommand.workflowName())
                || !Objects.equals(eventSubject.getWorkflowVersion(), concreteCommand.workflowVersion())
                || (eventSubject.hasPriority()
                && !Objects.equals(eventSubject.getPriority(), concreteCommand.priority()))
                || (eventSubject.hasConcurrencyGroupId()
                && !Objects.equals(eventSubject.getConcurrencyGroupId(), concreteCommand.concurrencyGroupId()))
                || (eventSubject.getLabelsCount() > 0
                && !Objects.equals(eventSubject.getLabelsMap(), concreteCommand.labels()))
                || (eventSubject.hasArgument()
                && !Objects.equals(eventSubject.getArgument(), concreteCommand.argument()))) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but it does not match \
                    the corresponding %s: event=%s, command=%s""".formatted(
                    ChildRunCreated.class.getSimpleName(),
                    event.getId(),
                    CreateChildRunCommand.class.getSimpleName(),
                    DebugFormat.singleLine().toString(eventSubject),
                    concreteCommand));
        }

        pendingCommandByEventId.remove(event.getId());
    }

    private void onChildRunCompleted(final Event event) {
        final ChildRunCompleted eventSubject = event.getChildRunCompleted();
        final int createdEventId = eventSubject.getChildRunCreatedEventId();
        logger().debug("Child workflow run failed for event ID {}", createdEventId);

        final Event createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasChildRunCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ChildRunCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ChildRunCompleted.class.getSimpleName(),
                    createdEventId));
        }

        awaitable.complete(eventSubject.hasResult() ? eventSubject.getResult() : null);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onChildRunFailed(final Event event) {
        final ChildRunFailed eventSubject = event.getChildRunFailed();
        final int createdEventId = eventSubject.getChildRunCreatedEventId();
        logger().debug("Child workflow run failed for event ID {}", createdEventId);

        final Event createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasChildRunCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ChildRunCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ChildRunFailed.class.getSimpleName(),
                    createdEventId));
        }

        final var exception = new ChildWorkflowFailureException(
                UUID.fromString(createdEvent.getChildRunCreated().getRunId()),
                createdEvent.getChildRunCreated().getWorkflowName(),
                createdEvent.getChildRunCreated().getWorkflowVersion(),
                FailureConverter.toException(eventSubject.getFailure()));

        awaitable.completeExceptionally(exception);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onTimerCreated(final Event event) {
        logger().debug("Timer created for event ID {}", event.getId());
        final TimerCreated eventSubject = event.getTimerCreated();

        final WorkflowCommand command = pendingCommandByEventId.get(event.getId());
        if (command == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    command was found for it""".formatted(
                    TimerCreated.class.getSimpleName(),
                    event.getId()));
        } else if (!(command instanceof final CreateTimerCommand concreteCommand)) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but the corresponding \
                    command is of type %s (expected %s)""".formatted(
                    TimerCreated.class.getSimpleName(),
                    event.getId(),
                    command.getClass().getSimpleName(),
                    CreateTimerCommand.class.getSimpleName()));
        } else if (!Objects.equals(eventSubject.getName(), concreteCommand.name())
                || !Objects.equals(eventSubject.getElapseAt(), toTimestamp(concreteCommand.elapseAt()))) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but it does not match \
                    the corresponding %s: event=%s, command=%s""".formatted(
                    TimerCreated.class.getSimpleName(),
                    event.getId(),
                    CreateTimerCommand.class.getSimpleName(),
                    DebugFormat.singleLine().toString(eventSubject),
                    concreteCommand));
        }

        pendingCommandByEventId.remove(event.getId());
    }

    private void onTimerElapsed(final Event event) {
        final TimerElapsed eventSubject = event.getTimerElapsed();
        final int createdEventId = eventSubject.getTimerCreatedEventId();
        logger().debug("Timer elapsed for event ID {}", createdEventId);

        final Event createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasTimerCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            TimerCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(event.getId());
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    TimerElapsed.class.getSimpleName(),
                    event.getId()));
        }

        pendingAwaitableByEventId.remove(event.getId());
        awaitable.complete(null);
    }

    private void onSideEffectExecuted(final Event event) {
        final SideEffectExecuted eventSubject = event.getSideEffectExecuted();
        final int eventId = eventSubject.getSideEffectEventId();
        logger().debug("Side effect executed for event ID {}", eventId);

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(eventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    SideEffectExecuted.class.getSimpleName(),
                    eventId));
        }

        pendingAwaitableByEventId.remove(eventId);
        awaitable.complete(eventSubject.hasResult()
                ? eventSubject.getResult()
                : null);
    }

    private void onExternalEventReceived(final Event event) {
        final String externalEventId = event.getExternalEventReceived().getId();
        logger().debug("External event received for ID {}", externalEventId);

        final Payload externalEventContent = event.getExternalEventReceived().hasPayload()
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

    private void complete(final @Nullable R result) {
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

    private void continueAsNew(final @Nullable Payload argument) {
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

    private void requireNotInSideEffect(final String message) {
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
