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
import org.dependencytrack.workflow.persistence.WorkflowRunLogEntryRow;
import org.dependencytrack.workflow.serialization.SerializationException;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.workflow.model.WorkflowEventType.ACTIVITY_RUN_COMPLETED;
import static org.dependencytrack.workflow.model.WorkflowEventType.ACTIVITY_RUN_QUEUED;
import static org.dependencytrack.workflow.model.WorkflowEventType.ACTIVITY_RUN_STARTED;

public final class WorkflowRunContext<A> extends WorkflowTaskContext<A> {

    private final Logger logger;
    private final WorkflowEngine engine;
    private List<WorkflowRunLogEntryRow> log;

    WorkflowRunContext(
            final Class<?> runnerClass,
            final WorkflowEngine engine,
            final UUID taskId,
            final String taskQueue,
            final Integer taskPriority,
            final UUID runId,
            final A arguments) {
        super(taskId, taskQueue, taskPriority, runId, arguments);
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

        WorkflowRunLogEntryRow queuedEvent = null;
        WorkflowRunLogEntryRow completedEvent = null;
        for (final WorkflowRunLogEntryRow historyEntry : getLog()) {
            if (!activityName.equals(historyEntry.activityName())
                || !invocationId.equals(historyEntry.activityInvocationId())) {
                continue;
            }

            if (historyEntry.eventType() == ACTIVITY_RUN_QUEUED) {
                queuedEvent = historyEntry;
            } else if (historyEntry.eventType() == ACTIVITY_RUN_COMPLETED && queuedEvent != null) {
                completedEvent = historyEntry;
                break;
            }
        }

        // TODO: If there is a pending execution already in the history,
        //  don't request a new one. Register a future for its result instead.

        if (queuedEvent == null || completedEvent == null || !argumentsMatch(arguments).test(queuedEvent)) {
            logger.info("Activity completion not found in history; Triggering execution");
            final String functionResult = engine.callActivity(
                    taskId(), runId(), activityName, invocationId, engine.serializeJson(arguments), timeout);
            return engine.deserializeJson(functionResult, resultClass);
        }

        logger.info("Completion of activity %s#%s found in history event %s from %s".formatted(
                activityName, invocationId, completedEvent.eventId(), completedEvent.timestamp()));

        return engine.deserializeJson(completedEvent.result(), resultClass);
    }

    public <AA, AR> AR callLocalActivity(
            final String activityName,
            final String invocationId,
            final AA arguments,
            final Class<AR> resultClass,
            final Function<AA, AR> activityFunction) {
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(invocationId, "invocationId must not be null");
        requireNonNull(activityFunction, "activityFunction must not be null");

        WorkflowRunLogEntryRow startedEvent = null;
        WorkflowRunLogEntryRow completedEvent = null;
        for (final WorkflowRunLogEntryRow historyEntry : getLog()) {
            if (!activityName.equals(historyEntry.activityName())
                || !invocationId.equals(historyEntry.activityInvocationId())) {
                continue;
            }

            if (historyEntry.eventType() == ACTIVITY_RUN_STARTED) {
                startedEvent = historyEntry;
            } else if (historyEntry.eventType() == ACTIVITY_RUN_COMPLETED && startedEvent != null) {
                completedEvent = historyEntry;
                break;
            }
        }

        if (startedEvent == null || completedEvent == null || !argumentsMatch(arguments).test(startedEvent)) {
            logger.info("Completion of local activity %s#%s not found in history"
                    .formatted(activityName, invocationId));
            return engine.callLocalActivity(taskId(), runId(), activityName, invocationId, arguments, activityFunction);
        }

        logger.info("Completion of local activity %s#%s found in history event %s from %s".formatted(
                activityName, invocationId, completedEvent.eventId(), completedEvent.timestamp()));

        return engine.deserializeJson(completedEvent.result(), resultClass);
    }

    private <T> Predicate<WorkflowRunLogEntryRow> argumentsMatch(final T arguments) {
        if (arguments == null) {
            return entry -> {
                if (entry.arguments() != null) {
                    logger.warn("Argument mismatch: null -> %s".formatted(entry.arguments()));
                    return false;
                }

                return true;
            };
        }

        final JsonNode argumentsJson = engine.jsonMapper().convertValue(arguments, JsonNode.class);

        return entry -> {
            if (entry.arguments() == null) {
                logger.warn("Arguments mismatch: %s -> null".formatted(arguments));
                return false;
            }

            final JsonNode logEntryArgumentsJson;
            try {
                logEntryArgumentsJson = engine.jsonMapper().readTree(entry.arguments());
            } catch (JsonProcessingException e) {
                throw new SerializationException("Failed to deserialize log entry arguments", e);
            }
            if (!argumentsJson.equals(logEntryArgumentsJson)) {
                logger.warn("Arguments mismatch: %s -> %s".formatted(logEntryArgumentsJson, argumentsJson));
                return false;
            }

            return true;
        };
    }

    private List<WorkflowRunLogEntryRow> getLog() {
        if (log == null) {
            log = engine.getWorkflowRunLog(runId());
        }

        return log;
    }

}
