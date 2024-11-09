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
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.persistence.WorkflowEventColumnMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import static net.logstash.logback.util.StringUtils.trimToNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class WorkflowActivityResultCompleter implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowActivityResultCompleter.class);

    private final AtomicBoolean isStopped = new AtomicBoolean(false);

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

    private final Map<UUID, ActivityResultWatch> watchByActivityRunId = new ConcurrentHashMap<>();

    @Override
    public void run() {
        while (!isStopped.get()) {
            watchByActivityRunId.values().removeIf(ActivityResultWatch::isCancelled);

            if (watchByActivityRunId.isEmpty()) {
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
            for (final UUID activityRunId : watchByActivityRunId.keySet()) {
                i++;

                filterParts.add("\"ACTIVITY_RUN_ID\" = :activityRunId%d".formatted(i));
                filterParams.put("activityRunId" + i, activityRunId);
            }

            final var subQueries = new ArrayList<String>();
            for (final String filterPart : filterParts) {
                subQueries.add("""
                                       SELECT "EVENT"
                                         FROM "WORKFLOW_RUN_LOG"
                                        WHERE "EVENT_TYPE" IN ('ACTIVITY_RUN_COMPLETED', 'ACTIVITY_RUN_FAILED')
                                        AND \
                                       """ + filterPart);
            }

            final List<WorkflowEvent> events = withJdbiHandle(handle -> handle
                    .createQuery(String.join(" UNION ALL ", subQueries))
                    .bindMap(filterParams)
                    .map(new WorkflowEventColumnMapper())
                    .list());
            for (final WorkflowEvent event : events) {
                final UUID activityRunId = extractActivityRunId(event);
                final ActivityResultWatch watch = watchByActivityRunId.get(activityRunId);
                if (watch != null) {
                    if (event.getSubjectCase() == WorkflowEvent.SubjectCase.ACTIVITY_RUN_COMPLETED) {
                        watch.result().complete(trimToNull(event.getActivityRunCompleted().getResult()));
                        LOGGER.debug("Completed %s".formatted(activityRunId));
                        watchByActivityRunId.remove(activityRunId);
                    } else if (event.getSubjectCase() == WorkflowEvent.SubjectCase.ACTIVITY_RUN_FAILED
                               && !event.getActivityRunFailed().hasNextAttemptAt()) {
                        final var exception = new WorkflowActivityFailedException(
                                event.getActivityRunFailed().getFailureDetails());
                        watch.result().completeExceptionally(exception);
                        LOGGER.debug("Completed %s exceptionally".formatted(activityRunId));
                        watchByActivityRunId.remove(activityRunId);
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

    ActivityResultWatch watchActivityResult(final UUID activityRunId) {
        final var watch = new ActivityResultWatch();
        final ActivityResultWatch existingWatch = watchByActivityRunId.putIfAbsent(activityRunId, watch);
        return existingWatch != null ? existingWatch : watch;
    }

    private static UUID extractActivityRunId(final WorkflowEvent event) {
        final String activityRunId = switch (event.getSubjectCase()) {
            case ACTIVITY_RUN_REQUESTED -> event.getActivityRunRequested().getRunId();
            case ACTIVITY_RUN_QUEUED -> event.getActivityRunQueued().getRunId();
            case ACTIVITY_RUN_STARTED -> event.getActivityRunStarted().getRunId();
            case ACTIVITY_RUN_COMPLETED -> event.getActivityRunCompleted().getRunId();
            case ACTIVITY_RUN_FAILED -> event.getActivityRunFailed().getRunId();
            default -> throw new IllegalStateException("Not an activity run event");
        };

        return UUID.fromString(activityRunId);
    }

}
