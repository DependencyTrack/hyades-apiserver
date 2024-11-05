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
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.dependencytrack.workflow.persistence.WorkflowRunHistoryEntryRow;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_ACTIVITY_RUN_COMPLETED;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_ACTIVITY_RUN_QUEUED;

public class WorkflowRunContext<T> {

    private static final Logger LOGGER = Logger.getLogger(WorkflowRunContext.class);

    private final WorkflowEngine workflowEngine;
    private final UUID workflowRunId;
    private final List<WorkflowRunHistoryEntryRow> history;

    WorkflowRunContext(
            final WorkflowEngine workflowEngine,
            final UUID workflowRunId,
            final List<WorkflowRunHistoryEntryRow> history) {
        this.workflowEngine = workflowEngine;
        this.workflowRunId = workflowRunId;
        this.history = history;
    }

    public <A, R> CompletableFuture<R> callActivity(
            final String name,
            final String invocationId,
            final A arguments,
            final Class<R> resultClass) {
        requireNonNull(name, "name must not be null");
        requireNonNull(invocationId, "invocationId must not be null");

        WorkflowRunHistoryEntryRow queuedEvent = null;
        WorkflowRunHistoryEntryRow completedEvent = null;
        for (final WorkflowRunHistoryEntryRow historyEntry : history) {
            if (!name.equals(historyEntry.activityName())
                || !invocationId.equals(historyEntry.activityInvocationId())) {
                continue;
            }

            if (WORKFLOW_ACTIVITY_RUN_QUEUED.name().equals(historyEntry.eventType())) {
                queuedEvent = historyEntry;
            } else if (WORKFLOW_ACTIVITY_RUN_COMPLETED.name().equals(historyEntry.eventType()) && queuedEvent != null) {
                completedEvent = historyEntry;
                break;
            }
        }

        if (queuedEvent == null || completedEvent == null || !argumentsMatch(arguments).test(queuedEvent)) {
            LOGGER.info("Activity completion not found in history; Triggering execution");
            return workflowEngine
                    .callActivity(workflowRunId, name, invocationId, serializeJson(arguments))
                    .thenApply(resultBytes -> deserializeJson(resultBytes, resultClass));
        }

        LOGGER.info("Completion of activity %s#%s found in history entry %d from %s".formatted(
                name, invocationId, completedEvent.id(), completedEvent.timestamp()));

        return CompletableFuture.completedFuture(deserializeJson(completedEvent.result(), resultClass));
    }

    private static <T> Predicate<WorkflowRunHistoryEntryRow> argumentsMatch(final T arguments) {
        if (arguments == null) {
            return entry -> {
                if (entry.arguments() != null) {
                    LOGGER.warn("Argument mismatch: null -> %s".formatted(entry.arguments()));
                    return false;
                }

                return true;
            };
        }

        final var jsonMapper = new JsonMapper();
        final JsonNode argumentsJsonNode = jsonMapper.convertValue(arguments, JsonNode.class);

        return entry -> {
            if (entry.arguments() == null) {
                LOGGER.warn("Arguments mismatch: %s -> null".formatted(arguments));
                return false;
            }

            final JsonNode entryArgumentsJsonNode;
            try {
                entryArgumentsJsonNode = jsonMapper.readTree(entry.arguments());
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            if (!argumentsJsonNode.equals(entryArgumentsJsonNode)) {
                LOGGER.warn("Arguments mismatch: %s -> %s".formatted(argumentsJsonNode, entryArgumentsJsonNode));
                return false;
            }

            return true;
        };
    }

    private static <T> String serializeJson(final T object) {
        if (object == null) {
            return null;
        }

        try {
            return new JsonMapper().writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private static <T> T deserializeJson(final String json, final Class<T> clazz) {
        if (json == null || clazz == null) {
            return null;
        }

        try {
            return new JsonMapper().readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
