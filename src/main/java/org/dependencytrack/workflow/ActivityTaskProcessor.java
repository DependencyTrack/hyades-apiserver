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

import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskCompleted;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

final class ActivityTaskProcessor<A, R> implements TaskProcessor<ActivityTask> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ActivityTaskProcessor.class);

    private final WorkflowEngine engine;
    private final String activityName;
    private final ActivityRunner<A, R> activityRunner;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;
    private final Duration taskLockTimeout;

    public ActivityTaskProcessor(
            final WorkflowEngine engine,
            final String activityName,
            final ActivityRunner<A, R> activityRunner,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration taskLockTimeout) {
        this.engine = engine;
        this.activityName = activityName;
        this.activityRunner = activityRunner;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
        this.taskLockTimeout = taskLockTimeout;
    }

    @Override
    public String taskName() {
        return activityName;
    }

    @Override
    public List<ActivityTask> poll(final int limit) {
        return engine.pollActivityTasks(activityName, limit, taskLockTimeout);
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

    private void processInternal(final ActivityTask task) {
        final var ctx = new ActivityRunContext<>(
                engine,
                task.workflowRunId(),
                task.scheduledEventId(),
                argumentConverter.convertFromPayload(task.argument()),
                activityRunner,
                taskLockTimeout,
                task.lockedUntil());

        try {
            final Optional<R> result;
            try (ctx) {
                result = activityRunner.run(ctx);
            }

            try {
                final var subjectBuilder = ActivityTaskCompleted.newBuilder()
                        .setTaskScheduledEventId(task.scheduledEventId());
                result.ifPresent(r -> subjectBuilder.setResult(resultConverter.convertToPayload(r)));

                // TODO: Retry on TimeoutException
                engine.completeActivityTask(task, result.map(resultConverter::convertToPayload).orElse(null)).join();
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
