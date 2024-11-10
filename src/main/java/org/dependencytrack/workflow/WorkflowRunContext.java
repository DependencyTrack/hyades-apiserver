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
import org.apache.commons.lang3.ArrayUtils;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventResumeCondition;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunQueued;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.serialization.Serde;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

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
            final A arguments) {
        super(taskId, workflowName, workflowVersion, workflowRunId, arguments);
        this.logger = Logger.getLogger(runnerClass);
        this.engine = engine;
    }

    // TODO: Accept a Class<? extends WorkflowActivityRunner> instead of activityName
    //  such that we can ensure that argument and result types of the activity
    //  match the given serdes.
    // TODO: Retry policy
    public <AA, AR> Optional<AR> callActivity(
            final String activityName,
            final String invocationId,
            final AA arguments,
            final Serde<AA> argumentsSerde,
            final Serde<AR> resultSerde,
            final Duration timeout) {
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(invocationId, "invocationId must not be null");
        requireNonNull(timeout, "timeout must not be null");

        WorkflowActivityRunQueued queuedEvent = null;
        WorkflowActivityRunCompleted completedEvent = null;
        WorkflowActivityRunFailed failedEvent = null;
        for (final WorkflowEvent logEvent : getEventLog()) {
            if (logEvent.hasActivityRunQueued()
                && logEvent.getActivityRunQueued().getActivityName().equals(activityName)
                && logEvent.getActivityRunQueued().getInvocationId().equals(invocationId)) {
                queuedEvent = logEvent.getActivityRunQueued();
                continue;
            }

            if (queuedEvent != null
                && logEvent.hasActivityRunCompleted()
                && logEvent.getActivityRunCompleted().getRunId().equals(queuedEvent.getRunId())) {
                logger.debug("Completion of activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                completedEvent = logEvent.getActivityRunCompleted();
                break;
            }

            if (queuedEvent != null
                && logEvent.hasActivityRunFailed()
                && logEvent.getActivityRunFailed().getRunId().equals(queuedEvent.getRunId())) {
                logger.debug("Failure of activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                failedEvent = logEvent.getActivityRunFailed();
                break;
            }
        }

        // TODO: If there is a pending execution already in the history,
        //  don't request a new one. Register a future for its result instead.

        final byte[] serializedArguments = argumentsSerde.serialize(arguments);
        if (queuedEvent == null || (completedEvent == null && failedEvent == null)
            || !argumentsMatch(serializedArguments).test(
                queuedEvent.hasArguments() ? queuedEvent.getArguments().toByteArray() : null)) {
            logger.debug("Activity completion not found in history; Triggering execution");
            return engine.callActivity(taskId(), workflowRunId(),
                    activityName, invocationId, serializedArguments, resultSerde, timeout);
        }

        if (failedEvent != null) {
            // TODO: Reconstruct exception from event (incl. Stacktrace), such that
            //  try-catch logic behaves as expected when replaying.
            throw new WorkflowActivityFailedException(failedEvent.getFailureDetails());
        }

        return completedEvent.hasResult()
                ? Optional.of(completedEvent.getResult().toByteArray()).map(resultSerde::deserialize)
                : Optional.empty();
    }

    // TODO: Accept a Class<? extends WorkflowActivityRunner> instead of activityName
    //  such that we can ensure that argument and result types of the activity
    //  match the given serdes.
    public <AA, AR> Optional<AR> callLocalActivity(
            final String activityName,
            final String invocationId,
            final AA arguments,
            final Serde<AA> argumentsSerde,
            final Serde<AR> resultSerde,
            final Function<AA, AR> activityFunction) {
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(invocationId, "invocationId must not be null");
        requireNonNull(activityFunction, "activityFunction must not be null");

        WorkflowActivityRunStarted startedEvent = null;
        WorkflowActivityRunCompleted completedEvent = null;
        WorkflowActivityRunFailed failedEvent = null;
        for (final WorkflowEvent logEvent : getEventLog()) {
            if (logEvent.hasActivityRunStarted()
                && logEvent.getActivityRunStarted().getActivityName().equals(activityName)
                && logEvent.getActivityRunStarted().getInvocationId().equals(invocationId)
                && logEvent.getActivityRunStarted().getIsLocal()) {
                startedEvent = logEvent.getActivityRunStarted();
                continue;
            }

            if (startedEvent != null
                && logEvent.hasActivityRunCompleted()
                && logEvent.getActivityRunCompleted().getRunId().equals(startedEvent.getRunId())) {
                logger.debug("Completion of local activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                completedEvent = logEvent.getActivityRunCompleted();
                break;
            }

            if (startedEvent != null
                && logEvent.hasActivityRunFailed()
                && logEvent.getActivityRunFailed().getRunId().equals(startedEvent.getRunId())) {
                logger.debug("Failure of local activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                failedEvent = logEvent.getActivityRunFailed();
                break;
            }
        }

        final byte[] serializedArguments = argumentsSerde.serialize(arguments);
        if (startedEvent == null || (completedEvent == null && failedEvent == null)
            || !argumentsMatch(serializedArguments).test(
                startedEvent.hasArguments() ? startedEvent.getArguments().toByteArray() : null)) {
            return engine.callLocalActivity(taskId(), workflowRunId(),
                    activityName, invocationId, arguments, serializedArguments, resultSerde, activityFunction);
        }

        if (failedEvent != null) {
            // TODO: Reconstruct exception from event (incl. Stacktrace), such that
            //  try-catch logic behaves as expected when replaying.
            throw new WorkflowActivityFailedException(failedEvent.getFailureDetails());
        }

        return completedEvent.hasResult()
                ? Optional.of(completedEvent.getResult().toByteArray()).map(resultSerde::deserialize)
                : Optional.empty();
    }

    public <T> Optional<T> awaitExternalEvent(final UUID externalEventId, final Serde<T> contentSerde) {
        requireNonNull(externalEventId, "externalEventId must not be null");

        ExternalEventReceived event = null;
        for (final WorkflowEvent logEvent : getEventLog()) {
            if (logEvent.getSubjectCase() == WorkflowEvent.SubjectCase.EXTERNAL_EVENT_RECEIVED
                && externalEventId.toString().equals(logEvent.getExternalEventReceived().getId())) {
                logger.debug("Awaited external event %s found in history event %s from %s".formatted(
                        logEvent.getExternalEventReceived().getId(), logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                event = logEvent.getExternalEventReceived();
                break;
            }
        }

        if (event == null) {
            throw new WorkflowRunSuspendedException(
                    ExternalEventResumeCondition.newBuilder()
                            .setExternalEventId(externalEventId.toString())
                            .build());
        }

        return event.hasContent()
                ? Optional.ofNullable(event.getContent().toByteArray()).map(contentSerde::deserialize)
                : Optional.empty();
    }

    private Predicate<byte[]> argumentsMatch(final byte[] argumentsBytes) {
        if (argumentsBytes == null) {
            return logEntryArgumentsBytes -> {
                if (logEntryArgumentsBytes != null) {
                    final String logEntryArgumentsPrefixB64 = Base64.getEncoder().encodeToString(
                            ArrayUtils.subarray(logEntryArgumentsBytes, 0, 32));
                    logger.warn("Argument mismatch: %s... -> null".formatted(logEntryArgumentsPrefixB64));
                    return false;
                }

                return true;
            };
        }

        return logEntryArgumentsBytes -> {
            if (logEntryArgumentsBytes == null) {
                final String argumentsPrefixB64 = Base64.getEncoder().encodeToString(
                        ArrayUtils.subarray(argumentsBytes, 0, 32));
                logger.warn("Arguments mismatch: null -> %s...".formatted(argumentsPrefixB64));
                return false;
            }

            if (!Arrays.equals(logEntryArgumentsBytes, argumentsBytes)) {
                final String argumentsPrefixB64 = Base64.getEncoder().encodeToString(
                        ArrayUtils.subarray(argumentsBytes, 0, 32));
                final String logEntryArgumentsPrefixB64 = Base64.getEncoder().encodeToString(
                        ArrayUtils.subarray(logEntryArgumentsBytes, 0, 32));
                logger.warn("Arguments mismatch: %s... -> %s...".formatted(logEntryArgumentsPrefixB64, argumentsPrefixB64));
                return false;
            }

            return true;
        };
    }

    private List<WorkflowEvent> getEventLog() {
        if (log == null) {
            // TODO: Any realistic chance of caching this?
            //  Ideally this query would skip log records where:
            //      timestamp <= log.getLast().getTimestamp()
            log = engine.getWorkflowRunLog(workflowRunId());
        }

        return log;
    }

}
