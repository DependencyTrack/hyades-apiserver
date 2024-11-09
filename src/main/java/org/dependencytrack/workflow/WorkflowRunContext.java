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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunQueued;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.serialization.SerializationException;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.StringUtils.trimToNull;

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

    // TODO: Retry policy
    public <AA, AR> AR callActivity(
            final String activityName,
            final String invocationId,
            final AA arguments,
            final Class<AR> resultClass,
            final Duration timeout) {
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(invocationId, "invocationId must not be null");
        requireNonNull(resultClass, "resultClass must not be null");
        requireNonNull(timeout, "timeout must not be null");

        WorkflowActivityRunQueued queuedEvent = null;
        WorkflowActivityRunCompleted completedEvent = null;
        WorkflowActivityRunFailed failedEvent = null;
        for (final WorkflowEvent logEvent : getLog()) {
            if (logEvent.hasActivityRunQueued()
                && logEvent.getActivityRunQueued().getActivityName().equals(activityName)
                && logEvent.getActivityRunQueued().getInvocationId().equals(invocationId)) {
                queuedEvent = logEvent.getActivityRunQueued();
                continue;
            }

            if (logEvent.hasActivityRunCompleted()
                && logEvent.getActivityRunCompleted().getActivityName().equals(activityName)
                && logEvent.getActivityRunCompleted().getInvocationId().equals(invocationId)) {
                logger.debug("Completion of activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                completedEvent = logEvent.getActivityRunCompleted();
                break;
            }

            if (logEvent.hasActivityRunFailed()
                && logEvent.getActivityRunFailed().getActivityName().equals(activityName)
                && logEvent.getActivityRunFailed().getInvocationId().equals(invocationId)) {
                logger.debug("Failure of activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                failedEvent = logEvent.getActivityRunFailed();
                break;
            }
        }

        // TODO: If there is a pending execution already in the history,
        //  don't request a new one. Register a future for its result instead.

        final String serializedArguments = engine.serializeJson(arguments);
        if (queuedEvent == null || (completedEvent == null && failedEvent == null)
            || !argumentsMatch(serializedArguments).test(trimToNull(queuedEvent.getArguments()))) {
            logger.debug("Activity completion not found in history; Triggering execution");
            final String activityResult = engine.callActivity(
                    taskId(), workflowRunId(), activityName, invocationId, serializedArguments, timeout);
            return engine.deserializeJson(activityResult, resultClass);
        }

        if (failedEvent != null) {
            throw new WorkflowActivityFailedException(failedEvent.getFailureDetails());
        }

        return engine.deserializeJson(trimToNull(completedEvent.getResult()), resultClass);
    }

    public <AA, AR> AR callLocalActivity(
            final String activityName,
            final String invocationId,
            final AA arguments,
            final Class<AR> resultClass,
            final Function<AA, AR> activityFunction) {
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(invocationId, "invocationId must not be null");
        requireNonNull(resultClass, "resultClass must not be null");
        requireNonNull(activityFunction, "activityFunction must not be null");

        WorkflowActivityRunStarted startedEvent = null;
        WorkflowActivityRunCompleted completedEvent = null;
        WorkflowActivityRunFailed failedEvent = null;
        for (final WorkflowEvent logEvent : getLog()) {
            if (logEvent.hasActivityRunStarted()
                && logEvent.getActivityRunStarted().getActivityName().equals(activityName)
                && logEvent.getActivityRunStarted().getInvocationId().equals(invocationId)
                && logEvent.getActivityRunStarted().getIsLocal()) {
                startedEvent = logEvent.getActivityRunStarted();
                continue;
            }

            if (logEvent.hasActivityRunCompleted()
                && logEvent.getActivityRunCompleted().getActivityName().equals(activityName)
                && logEvent.getActivityRunCompleted().getInvocationId().equals(invocationId)
                && logEvent.getActivityRunCompleted().getIsLocal()) {
                logger.debug("Completion of local activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                completedEvent = logEvent.getActivityRunCompleted();
                break;
            }

            if (logEvent.hasActivityRunFailed()
                && logEvent.getActivityRunFailed().getActivityName().equals(activityName)
                && logEvent.getActivityRunFailed().getInvocationId().equals(invocationId)
                && logEvent.getActivityRunFailed().getIsLocal()) {
                logger.debug("Failure of local activity %s#%s found in history event %s from %s".formatted(
                        activityName, invocationId, logEvent.getId(),
                        Instant.ofEpochMilli(Timestamps.toMillis(logEvent.getTimestamp()))));
                failedEvent = logEvent.getActivityRunFailed();
                break;
            }
        }

        final String serializedArguments = engine.serializeJson(arguments);
        if (startedEvent == null || (completedEvent == null && failedEvent == null)
            || !argumentsMatch(serializedArguments).test(trimToNull(startedEvent.getArguments()))) {
            return engine.callLocalActivity(taskId(), workflowRunId(), activityName, invocationId, arguments, activityFunction);
        }

        if (failedEvent != null) {
            throw new WorkflowActivityFailedException(failedEvent.getFailureDetails());
        }

        return engine.deserializeJson(trimToNull(completedEvent.getResult()), resultClass);
    }

    private <T> Predicate<String> argumentsMatch(final String arguments) {
        if (arguments == null) {
            return logEntryArguments -> {
                if (logEntryArguments != null) {
                    logger.warn("Argument mismatch: null -> %s".formatted(logEntryArguments));
                    return false;
                }

                return true;
            };
        }

        return logEntryArguments -> {
            if (logEntryArguments == null) {
                logger.warn("Arguments mismatch: %s -> null".formatted(arguments));
                return false;
            }

            final JsonNode argumentsJson;
            final JsonNode logEntryArgumentsJson;
            try {
                argumentsJson = engine.jsonMapper().readTree(arguments);
                logEntryArgumentsJson = engine.jsonMapper().readTree(logEntryArguments);
            } catch (JsonProcessingException e) {
                throw new SerializationException("Failed to deserialize arguments", e);
            }
            if (!argumentsJson.equals(logEntryArgumentsJson)) {
                logger.warn("Arguments mismatch: %s -> %s".formatted(logEntryArgumentsJson, argumentsJson));
                return false;
            }

            return true;
        };
    }

    private List<WorkflowEvent> getLog() {
        if (log == null) {
            log = engine.getWorkflowRunLog(workflowRunId());
        }

        return log;
    }

}
