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
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventAwaited;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunQueued;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunRequested;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.annotation.WorkflowActivity;
import org.dependencytrack.workflow.payload.PayloadConverter;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

public final class WorkflowRunContext<A> extends WorkflowTaskContext<A> {

    private final Logger logger;
    private final WorkflowEngine engine;
    private List<WorkflowEvent> log;

    WorkflowRunContext(
            final Class<?> runnerClass,
            final WorkflowEngine engine,
            final UUID taskId,
            final String workflowName,
            final int workflowVersion,
            final UUID workflowRunId,
            final A argument) {
        super(taskId, workflowName, workflowVersion, workflowRunId, argument);
        this.logger = Logger.getLogger(runnerClass);
        this.engine = engine;
    }

    public <AA, AR> Awaitable<AR> callActivity(
            final Class<? extends WorkflowActivityRunner<AA, AR>> activityClass,
            final String invocationId,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter) {
        final var activityAnnotation = activityClass.getAnnotation(WorkflowActivity.class);
        if (activityAnnotation == null) {
            throw new IllegalArgumentException();
        }

        return callActivity(activityAnnotation.name(), invocationId, argument, argumentConverter, resultConverter);
    }

    // TODO: Retry policy
    public <AA, AR> Awaitable<AR> callActivity(
            final String activityName,
            final String invocationId,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter) {
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(invocationId, "invocationId must not be null");

        final WorkflowPayload argumentPayload = argumentConverter.convertToPayload(argument).orElse(null);

        WorkflowActivityRunQueued queuedEvent = null;
        WorkflowActivityRunCompleted completedEvent = null;
        WorkflowActivityRunFailed failedEvent = null;
        for (final WorkflowEvent logEvent : getEventLog()) {
            if (queuedEvent == null
                && logEvent.hasActivityRunQueued()
                && logEvent.getActivityRunQueued().getActivityName().equals(activityName)
                && logEvent.getActivityRunQueued().getInvocationId().equals(invocationId)
                && argumentsMatch(logEvent.getActivityRunQueued().getArgument(), argumentPayload)) {
                queuedEvent = logEvent.getActivityRunQueued();
                continue;
            }

            if (queuedEvent != null
                && logEvent.hasActivityRunCompleted()
                && logEvent.getActivityRunCompleted().getCompletionId().equals(queuedEvent.getCompletionId())) {
                logger.debug("Completion of activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochSecond(0L, Timestamps.toNanos(logEvent.getTimestamp()))));
                completedEvent = logEvent.getActivityRunCompleted();
                break;
            }

            if (queuedEvent != null
                && logEvent.hasActivityRunFailed()
                && logEvent.getActivityRunFailed().getCompletionId().equals(queuedEvent.getCompletionId())) {
                logger.debug("Failure of activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochSecond(0L, Timestamps.toNanos(logEvent.getTimestamp()))));
                failedEvent = logEvent.getActivityRunFailed();
                break;
            }
        }

        if (completedEvent == null && failedEvent == null) {
            if (queuedEvent != null) {
                return new Awaitable.Single<>(UUID.fromString(queuedEvent.getCompletionId()));
            }

            logger.debug("Activity completion not found in history; Triggering execution");
            return callActivity(taskId(), workflowRunId(), activityName, invocationId, argumentPayload);
        } else if (failedEvent != null) {
            // TODO: Reconstruct exception from event (incl. Stacktrace), such that
            //  try-catch logic behaves as expected when replaying.
            return new Awaitable.Single<>(
                    UUID.fromString(failedEvent.getCompletionId()),
                    new WorkflowActivityFailedException(failedEvent.getFailureDetails()));
        }

        return new Awaitable.Single<>(
                UUID.fromString(completedEvent.getCompletionId()),
                completedEvent.hasResult()
                        ? resultConverter.convertFromPayload(completedEvent.getResult()).orElse(null)
                        : null);
    }

    private <R> Awaitable<R> callActivity(
            final UUID invokingTaskId,
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final WorkflowPayload argumentPayload) {
        final var completionId = UUID.randomUUID();
        final var subjectBuilder = WorkflowActivityRunRequested.newBuilder()
                .setCompletionId(completionId.toString())
                .setActivityName(activityName)
                .setInvocationId(invocationId)
                .setInvokingTaskId(invokingTaskId.toString());
        if (argumentPayload != null) {
            subjectBuilder.setArgument(argumentPayload);
        }

        addToEventBuffer(WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setTimestamp(Timestamps.now())
                .setWorkflowRunId(workflowRunId.toString())
                .setActivityRunRequested(subjectBuilder.build())
                .build());

        return new Awaitable.Single<>(completionId);
    }

    public <AA, AR> Optional<AR> callLocalActivity(
            final String activityName,
            final String invocationId,
            final AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final Function<AA, Optional<AR>> activityFunction) {
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(invocationId, "invocationId must not be null");
        requireNonNull(activityFunction, "activityFunction must not be null");

        final WorkflowPayload argumentPayload = argumentConverter.convertToPayload(argument).orElse(null);

        WorkflowActivityRunStarted startedEvent = null;
        WorkflowActivityRunCompleted completedEvent = null;
        WorkflowActivityRunFailed failedEvent = null;
        for (final WorkflowEvent logEvent : getEventLog()) {
            if (startedEvent == null
                && logEvent.hasActivityRunStarted()
                && logEvent.getActivityRunStarted().getActivityName().equals(activityName)
                && logEvent.getActivityRunStarted().getInvocationId().equals(invocationId)
                && logEvent.getActivityRunStarted().getIsLocal()
                && argumentsMatch(logEvent.getActivityRunStarted().getArgument(), argumentPayload)) {
                startedEvent = logEvent.getActivityRunStarted();
                continue;
            }

            if (startedEvent != null
                && logEvent.hasActivityRunCompleted()
                && logEvent.getActivityRunCompleted().getCompletionId().equals(startedEvent.getCompletionId())) {
                logger.debug("Completion of local activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochSecond(0L, Timestamps.toNanos(logEvent.getTimestamp()))));
                completedEvent = logEvent.getActivityRunCompleted();
                break;
            }

            if (startedEvent != null
                && logEvent.hasActivityRunFailed()
                && logEvent.getActivityRunFailed().getCompletionId().equals(startedEvent.getCompletionId())) {
                logger.debug("Failure of local activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochSecond(0L, Timestamps.toNanos(logEvent.getTimestamp()))));
                failedEvent = logEvent.getActivityRunFailed();
                break;
            }
        }

        if (startedEvent == null || (completedEvent == null && failedEvent == null)) {
            return callLocalActivity(taskId(), workflowRunId(),
                    activityName, invocationId, argument, argumentPayload, resultConverter, activityFunction);
        } else if (failedEvent != null) {
            // TODO: Reconstruct exception from event (incl. Stacktrace), such that
            //  try-catch logic behaves as expected when replaying.
            throw new WorkflowActivityFailedException(failedEvent.getFailureDetails());
        }

        return completedEvent.hasResult()
                ? resultConverter.convertFromPayload(completedEvent.getResult())
                : Optional.empty();
    }

    private <AA, AR> Optional<AR> callLocalActivity(
            final UUID invokingTaskId,
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final AA argument,
            final WorkflowPayload argumentPayload,
            final PayloadConverter<AR> resultConverter,
            final Function<AA, Optional<AR>> activityFunction) {
        final var completionId = UUID.randomUUID();
        final var executionStartedBuilder = WorkflowActivityRunStarted.newBuilder()
                .setCompletionId(completionId.toString())
                .setActivityName(activityName)
                .setInvocationId(invocationId)
                .setIsLocal(true)
                .setInvokingTaskId(invokingTaskId.toString());
        if (argumentPayload != null) {
            executionStartedBuilder.setArgument(argumentPayload);
        }
        addToEventBuffer(WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setWorkflowRunId(workflowRunId.toString())
                .setTimestamp(Timestamps.now())
                .setActivityRunStarted(executionStartedBuilder.build())
                .build());

        try {
            final Optional<AR> optionalResult = activityFunction.apply(argument);

            final var executionCompletedBuilder = WorkflowActivityRunCompleted.newBuilder()
                    .setCompletionId(completionId.toString())
                    .setActivityName(activityName)
                    .setInvocationId(invocationId)
                    .setIsLocal(true)
                    .setInvokingTaskId(invokingTaskId.toString());
            optionalResult
                    .flatMap(resultConverter::convertToPayload)
                    .ifPresent(executionCompletedBuilder::setResult);

            addToEventBuffer(WorkflowEvent.newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setWorkflowRunId(workflowRunId.toString())
                    .setTimestamp(Timestamps.now())
                    .setActivityRunCompleted(executionCompletedBuilder.build())
                    .build());

            return optionalResult;
        } catch (RuntimeException e) {
            addToEventBuffer(WorkflowEvent.newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setWorkflowRunId(workflowRunId.toString())
                    .setTimestamp(Timestamps.now())
                    .setActivityRunFailed(WorkflowActivityRunFailed.newBuilder()
                            .setCompletionId(completionId.toString())
                            .setActivityName(activityName)
                            .setInvocationId(invocationId)
                            .setIsLocal(true)
                            .setFailureDetails(e.getMessage() != null
                                    ? e.getMessage()
                                    : e.getClass().getName())
                            .setInvokingTaskId(invokingTaskId.toString())
                            .build())
                    .build());

            throw new WorkflowActivityFailedException(e);
        }
    }

    public <T> Awaitable<T> awaitExternalEvent(
            final UUID externalEventId,
            final PayloadConverter<T> payloadConverter) {
        requireNonNull(externalEventId, "externalEventId must not be null");

        ExternalEventAwaited awaitedEvent = null;
        ExternalEventReceived receivedEvent = null;
        for (final WorkflowEvent logEvent : getEventLog()) {
            if (awaitedEvent == null
                && logEvent.hasExternalEventAwaited()
                && logEvent.getExternalEventAwaited().getExternalEventId().equals(externalEventId.toString())) {
                awaitedEvent = logEvent.getExternalEventAwaited();
                continue;
            }

            if (awaitedEvent != null
                && logEvent.hasExternalEventReceived()
                && externalEventId.toString().equals(logEvent.getExternalEventReceived().getId())) {
                logger.debug("Awaited external event %s found in history event %s from %s".formatted(
                        logEvent.getExternalEventReceived().getId(), logEvent.getId(),
                        Instant.ofEpochSecond(0L, Timestamps.toNanos(logEvent.getTimestamp()))));
                receivedEvent = logEvent.getExternalEventReceived();
                break;
            }
        }

        if (receivedEvent == null) {
            if (awaitedEvent != null) {
                return new Awaitable.Single<>(UUID.fromString(awaitedEvent.getCompletionId()));
            }

            final UUID completionId = UUID.randomUUID();
            addToEventBuffer(WorkflowEvent.newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setWorkflowRunId(workflowRunId().toString())
                    .setTimestamp(Timestamps.now())
                    .setExternalEventAwaited(ExternalEventAwaited.newBuilder()
                            .setCompletionId(completionId.toString())
                            .setExternalEventId(externalEventId.toString())
                            .setInvokingTaskId(taskId().toString())
                            .build())
                    .build());

            return new Awaitable.Single<>(completionId);
        }

        return new Awaitable.Single<>(
                UUID.fromString(awaitedEvent.getCompletionId()),
                receivedEvent.hasPayload()
                        ? payloadConverter.convertFromPayload(receivedEvent.getPayload()).orElse(null)
                        : null);
    }

    private boolean argumentsMatch(WorkflowPayload left, WorkflowPayload right) {
        if (WorkflowPayload.getDefaultInstance().equals(left)) {
            left = null;
        }
        if (WorkflowPayload.getDefaultInstance().equals(right)) {
            right = null;
        }

        if (left == null) {
            if (right != null) {
                logger.warn("Argument mismatch: null -> %s".formatted(right));
                return false;
            }

            return true;
        }

        if (right == null) {
            logger.warn("Arguments mismatch: %s -> null".formatted(left));
            return false;
        }

        if (!Objects.equals(left, right)) {
            logger.warn("Arguments mismatch: %s... -> %s...".formatted(left, right));
            return false;
        }

        return true;
    }

    private List<WorkflowEvent> getEventLog() {
        if (log == null) {
            // TODO: Any realistic chance of caching this?
            //  Ideally this query would skip log records where:
            //      timestamp <= log.getLast().getTimestamp()
            log = engine.getWorkflowRunEventLog(workflowRunId());
        }

        return log;
    }

}
