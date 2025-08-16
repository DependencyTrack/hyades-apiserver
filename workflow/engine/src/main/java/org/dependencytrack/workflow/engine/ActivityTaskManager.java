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

import org.dependencytrack.proto.workflow.api.v1.ActivityTaskCompleted;
import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.dependencytrack.workflow.engine.MetadataRegistry.ActivityMetadata;
import org.dependencytrack.workflow.engine.api.ActivityGroup;
import org.dependencytrack.workflow.engine.persistence.command.PollActivityTaskCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.List;
import java.util.concurrent.TimeoutException;

final class ActivityTaskManager implements TaskManager<ActivityTask> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ActivityTaskManager.class);

    private final WorkflowEngineImpl engine;
    private final ActivityGroup activityGroup;
    private final MetadataRegistry metadataRegistry;
    private final List<PollActivityTaskCommand> pollCmds;

    ActivityTaskManager(
            final WorkflowEngineImpl engine,
            final ActivityGroup activityGroup,
            final MetadataRegistry metadataRegistry) {
        this.engine = engine;
        this.activityGroup = activityGroup;
        this.metadataRegistry = metadataRegistry;
        this.pollCmds = activityGroup.activityNames().stream()
                .map(metadataRegistry::getActivityMetadata)
                .map(metadata -> new PollActivityTaskCommand(metadata.name(), metadata.lockTimeout()))
                .toList();
    }

    @Override
    public String name() {
        return activityGroup.name();
    }

    @Override
    public List<ActivityTask> poll(final int limit) {
        return engine.pollActivityTasks(pollCmds, limit);
    }

    @Override
    public void process(final ActivityTask task) {
        try (var ignoredMdcWorkflowRunId = MDC.putCloseable("workflowRunId", task.workflowRunId().toString());
             var ignoredMdcWorkflowActivityName = MDC.putCloseable("workflowActivityName", task.activityName())) {
            processInternal(task);
        } catch (RuntimeException e) {
            LOGGER.error("Failed to process task; Abandoning it", e);
            abandon(task);
        }
    }

    @Override
    public void abandon(final ActivityTask task) {
        try {
            // TODO: Retry on TimeoutException
            engine.abandonActivityTask(task).join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for task abandonment to be acknowledged", e);
        } catch (TimeoutException e) {
            throw new RuntimeException("Timed out while waiting for task abandonment to be acknowledged", e);
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void processInternal(final ActivityTask task) {
        if (!activityGroup.activityNames().contains(task.activityName())) {
            throw new IllegalStateException(
                    "Received task for activity %s which is not part of the configured activity group %s".formatted(
                            task.activityName(), activityGroup.name()));
        }

        final ActivityMetadata activityMetadata = metadataRegistry.getActivityMetadata(task.activityName());

        final var ctx = new ActivityContextImpl<>(
                engine,
                task.workflowRunId(),
                task.scheduledEventId(),
                activityMetadata.executor(),
                activityMetadata.lockTimeout(),
                task.lockedUntil(),
                activityMetadata.heartbeatEnabled());
        final var arg = activityMetadata.argumentConverter().convertFromPayload(task.argument());

        try {
            final WorkflowPayload result;
            try (ctx) {
                final Object activityResult = activityMetadata.executor().execute(ctx, arg);
                result = activityMetadata.resultConverter().convertToPayload(activityResult);
            }

            try {
                final var subjectBuilder = ActivityTaskCompleted.newBuilder()
                        .setTaskScheduledEventId(task.scheduledEventId());
                if (result != null) {
                    subjectBuilder.setResult(result);
                }

                // TODO: Retry on TimeoutException
                engine.completeActivityTask(task, result).join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.warn("Interrupted while waiting for task completion to be acknowledged", e);
            } catch (TimeoutException e) {
                throw new RuntimeException("Timed out while waiting for task completion to be acknowledged", e);
            }
        } catch (Exception e) {
            try {
                // TODO: Retry on TimeoutException
                engine.failActivityTask(task, e).join();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                LOGGER.warn("Interrupted while waiting for task failure to be acknowledged", ex);
            } catch (TimeoutException ex) {
                throw new RuntimeException("Timed out while waiting for task failure to be acknowledged", ex);
            }
        }
    }

}
