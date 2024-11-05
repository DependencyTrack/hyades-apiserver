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
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class WorkflowActivityResultFutureCompleter implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowActivityResultFutureCompleter.class);

    private record Foo(UUID workflowRunId, String activityName, String invocationId) {
    }

    public record Bar(
            UUID workflowRunId,
            String activityName,
            String activityInvocationId,
            String eventType,
            String result) {
    }

    private final Map<Foo, CompletableFuture<String>> futures = new ConcurrentHashMap<>();

    @Override
    public void run() {
        while (true) {
            if (futures.isEmpty()) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(e);
                }
                continue;
            }

            var filterParts = new ArrayList<String>();
            var filterParams = new HashMap<String, Object>();

            var i = 0;
            for (final Foo foo : futures.keySet()) {
                i++;

                filterParts.add("""
                        "WORKFLOW_RUN_ID" = :workflowRunId%d \
                        AND "ACTIVITY_NAME" = :activityName%d \
                        AND "ACTIVITY_INVOCATION_ID" = :invocationId%d \
                        """.formatted(i, i, i));
                filterParams.put("workflowRunId" + i, foo.workflowRunId());
                filterParams.put("activityName" + i, foo.activityName());
                filterParams.put("invocationId" + i, foo.invocationId());
            }

            final var subQueries = new ArrayList<String>();
            for (final String filterPart : filterParts) {
                subQueries.add("""
                                       SELECT "WORKFLOW_RUN_ID"
                                            , "ACTIVITY_NAME"
                                            , "ACTIVITY_INVOCATION_ID"
                                            , "EVENT_TYPE"
                                            , "RESULT"
                                         FROM "WORKFLOW_RUN_EVENT_HISTORY"
                                        WHERE "EVENT_TYPE" IN ('WORKFLOW_ACTIVITY_RUN_COMPLETED', 'WORKFLOW_ACTIVITY_RUN_FAILED')
                                        AND \
                                       """ + filterPart);
            }

            final List<Bar> results = withJdbiHandle(handle -> handle
                    .createQuery(String.join(" UNION ALL ", subQueries))
                    .bindMap(filterParams)
                    .map(ConstructorMapper.of(Bar.class))
                    .list());
            for (final Bar bar : results) {
                final var foo = new Foo(bar.workflowRunId(), bar.activityName(), bar.activityInvocationId());
                final CompletableFuture<String> future = futures.get(foo);
                if (future != null) {
                    if ("WORKFLOW_ACTIVITY_RUN_COMPLETED".equals(bar.eventType())) {
                        future.complete(bar.result());
                        LOGGER.info("Resolved: " + foo);
                    } else if ("WORKFLOW_ACTIVITY_RUN_FAILED".equals(bar.eventType())) {
                        future.completeExceptionally(new RuntimeException(bar.result()));
                        LOGGER.warn("Resolved exceptionally: " + foo);
                    } else {
                        assert false;
                    }
                    futures.remove(foo);
                }
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        }
    }

    void watchFuture(
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final CompletableFuture<String> future) {
        futures.put(new Foo(workflowRunId, activityName, invocationId), future);
    }

}
