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
import org.dependencytrack.workflow.model.WorkflowEventType;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;

import jakarta.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class WorkflowActivityResultCompleter implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowActivityResultCompleter.class);

    private final AtomicBoolean isStopped = new AtomicBoolean(false);

    public record Bar(
            UUID workflowRunId,
            String activityName,
            String activityInvocationId,
            WorkflowEventType eventType,
            @Nullable String result,
            @Nullable String failureDetails) {
    }

    private record ActivityId(UUID workflowRunId, String functionName, String invocationId) {
    }

    static final class ActivityResultWatch {

        private final CompletableFuture<String> result;
        private final AtomicBoolean cancelled;

        ActivityResultWatch() {
            this.result = new CompletableFuture<>();
            this.cancelled = new AtomicBoolean(false);
        }

        CompletableFuture<String> result() {
            return result;
        }

        void cancel() {
            this.cancelled.set(true);
        }

        private boolean isCancelled() {
            return cancelled.get();
        }

    }

    private final Map<ActivityId, ActivityResultWatch> watchByActivityId = new ConcurrentHashMap<>();

    @Override
    public void run() {
        while (!isStopped.get()) {
            watchByActivityId.values().removeIf(ActivityResultWatch::isCancelled);

            if (watchByActivityId.isEmpty()) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    LOGGER.debug("Interrupted while sleeping");
                }

                continue;
            }

            var filterParts = new ArrayList<String>();
            var filterParams = new HashMap<String, Object>();

            var i = 0;
            for (final ActivityId activityId : watchByActivityId.keySet()) {
                i++;

                filterParts.add("""
                        "WORKFLOW_RUN_ID" = :workflowRunId%d \
                        AND "ACTIVITY_NAME" = :activityName%d \
                        AND "ACTIVITY_INVOCATION_ID" = :activityInvocationId%d \
                        """.formatted(i, i, i));
                filterParams.put("workflowRunId" + i, activityId.workflowRunId());
                filterParams.put("activityName" + i, activityId.functionName());
                filterParams.put("activityInvocationId" + i, activityId.invocationId());
            }

            final var subQueries = new ArrayList<String>();
            for (final String filterPart : filterParts) {
                subQueries.add("""
                                       SELECT "WORKFLOW_RUN_ID"
                                            , "ACTIVITY_NAME"
                                            , "ACTIVITY_INVOCATION_ID"
                                            , "EVENT_TYPE"
                                            , "RESULT"
                                            , "FAILURE_DETAILS"
                                         FROM "WORKFLOW_RUN_LOG"
                                        WHERE "EVENT_TYPE" IN ('ACTIVITY_RUN_COMPLETED', 'ACTIVITY_RUN_FAILED')
                                        AND \
                                       """ + filterPart);
            }

            final List<Bar> results = withJdbiHandle(handle -> handle
                    .createQuery(String.join(" UNION ALL ", subQueries))
                    .bindMap(filterParams)
                    .map(ConstructorMapper.of(Bar.class))
                    .list());
            for (final Bar bar : results) {
                final var functionId = new ActivityId(
                        bar.workflowRunId(), bar.activityName(), bar.activityInvocationId());
                final ActivityResultWatch watch = watchByActivityId.get(functionId);
                if (watch != null) {
                    if (bar.eventType() == WorkflowEventType.ACTIVITY_RUN_COMPLETED) {
                        watch.result().complete(bar.result());
                        LOGGER.info("Completed %s: %s".formatted(functionId, bar.result()));
                        watchByActivityId.remove(functionId);
                    } else if (bar.eventType() == WorkflowEventType.ACTIVITY_RUN_FAILED) {
                        final var exception = new WorkflowActivityFailedException(bar.failureDetails());
                        watch.result().completeExceptionally(exception);
                        LOGGER.warn("Completed %s exceptionally".formatted(functionId), exception);
                        watchByActivityId.remove(functionId);
                    } else {
                        assert false;
                    }
                }
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                LOGGER.debug("Interrupted while sleeping");
            }
        }
    }

    void shutdown() {
        isStopped.set(true);
    }

    ActivityResultWatch watchActivityResult(
            final UUID workflowRunId,
            final String activityName,
            final String invocationId) {
        final var functionId = new ActivityId(workflowRunId, activityName, invocationId);
        final var watch = new ActivityResultWatch();

        final ActivityResultWatch existingWatch = watchByActivityId.putIfAbsent(functionId, watch);
        return existingWatch != null ? existingWatch : watch;
    }

}
