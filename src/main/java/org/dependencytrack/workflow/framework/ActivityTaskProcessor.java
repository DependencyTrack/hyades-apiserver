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
package org.dependencytrack.workflow.framework;

import org.dependencytrack.workflow.framework.ActivityRegistry.RegisteredActivity;
import org.dependencytrack.workflow.framework.payload.PayloadConverter;
import org.dependencytrack.workflow.framework.persistence.model.PollActivityTaskCommand;
import org.dependencytrack.workflow.framework.proto.v1alpha1.ActivityTaskCompleted;
import org.dependencytrack.workflow.framework.proto.v1alpha1.WorkflowPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeoutException;

final class ActivityTaskProcessor<A, R> implements TaskProcessor<ActivityTask> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ActivityTaskProcessor.class);

    private final WorkflowEngine engine;
    private final ActivityRegistry activityRegistry;
    private final List<PollActivityTaskCommand> pollCommands;

    ActivityTaskProcessor(
            final WorkflowEngine engine,
            final ActivityRegistry activityRegistry) {
        this.engine = engine;
        this.activityRegistry = activityRegistry;
        this.pollCommands = activityRegistry.getActivities().entrySet().stream()
                .map(entry -> new PollActivityTaskCommand(
                        entry.getKey(), entry.getValue().lockTimeout()))
                .toList();
    }

    @Override
    public String taskName() {
        return activityRegistry.name(); // TODO
    }

    @Override
    public List<ActivityTask> poll(final int limit) {
        return engine.pollActivityTasks(pollCommands, limit);
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
        final RegisteredActivity registeredActivity = activityRegistry.getActivity(task.activityName());
        if (registeredActivity == null) {
            throw new IllegalStateException(
                    "Received task for activity %s, but it is not registered".formatted(task.activityName()));
        }

        final ActivityExecutor executor = registeredActivity.executor();
        final PayloadConverter argumentConverter = registeredActivity.argumentConverter();
        final PayloadConverter resultConverter = registeredActivity.resultConverter();
        final Duration lockTimeout = registeredActivity.lockTimeout();

        final var ctx = new ActivityContext<>(
                engine,
                task.workflowRunId(),
                task.scheduledEventId(),
                argumentConverter.convertFromPayload(task.argument()),
                executor,
                lockTimeout,
                task.lockedUntil());

        try {
            final WorkflowPayload result;
            try (ctx) {
                result = (WorkflowPayload) executor.execute(ctx)
                        .map(resultConverter::convertToPayload)
                        .orElse(null);
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
