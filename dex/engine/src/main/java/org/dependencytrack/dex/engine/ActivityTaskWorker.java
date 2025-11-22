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
package org.dependencytrack.dex.engine;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.MeterRegistry;
import org.dependencytrack.dex.engine.MetadataRegistry.ActivityMetadata;
import org.dependencytrack.dex.engine.persistence.command.PollActivityTaskCommand;
import org.dependencytrack.dex.proto.payload.v1.Payload;

import java.time.Duration;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeoutException;

import static java.util.Objects.requireNonNull;

final class ActivityTaskWorker extends AbstractTaskWorker<ActivityTask> {

    private final DexEngineImpl engine;
    private final MetadataRegistry metadataRegistry;
    private final String queueName;
    private final List<PollActivityTaskCommand> pollCommands;

    ActivityTaskWorker(
            final DexEngineImpl engine,
            final Duration minPollInterval,
            final IntervalFunction pollBackoffIntervalFunction,
            final MetadataRegistry metadataRegistry,
            final String queueName,
            final int maxConcurrency,
            final MeterRegistry meterRegistry) {
        super(minPollInterval, pollBackoffIntervalFunction, maxConcurrency, meterRegistry);
        this.engine = requireNonNull(engine, "engine must not be null");
        this.metadataRegistry = requireNonNull(metadataRegistry, "metadataRegistry must not be null");
        this.queueName = requireNonNull(queueName, "queueName must not be null");
        this.pollCommands = metadataRegistry.getAllActivityMetadata().stream()
                .map(metadata -> new PollActivityTaskCommand(metadata.name(), metadata.lockTimeout()))
                .toList();
    }

    @Override
    List<ActivityTask> poll(final int limit) {
        return engine.pollActivityTasks(queueName, pollCommands, limit);
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    void process(final ActivityTask task) {
        final ActivityMetadata activityMetadata;
        try {
            activityMetadata = metadataRegistry.getActivityMetadata(task.activityName());
        } catch (NoSuchElementException e) {
            logger.warn("Activity {} does not exist", task.activityName());
            abandon(task);
            return;
        }

        final var ctx = new ActivityContextImpl<>(
                engine,
                task.queueName(),
                task.workflowRunId(),
                task.createdEventId(),
                activityMetadata.executor(),
                activityMetadata.lockTimeout(),
                task.lockedUntil(),
                activityMetadata.heartbeatEnabled());
        final var arg = activityMetadata.argumentConverter().convertFromPayload(task.argument());

        try {
            final Payload result;
            try (ctx) {
                final Object activityResult = activityMetadata.executor().execute(ctx, arg);
                result = activityMetadata.resultConverter().convertToPayload(activityResult);
            }

            try {
                // TODO: Retry on TimeoutException
                engine.completeActivityTask(task, result).join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("Interrupted while waiting for task completion to be acknowledged", e);
            } catch (TimeoutException e) {
                throw new RuntimeException("Timed out while waiting for task completion to be acknowledged", e);
            }
        } catch (Exception e) {
            try {
                // TODO: Retry on TimeoutException
                engine.failActivityTask(task, e).join();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                logger.warn("Interrupted while waiting for task failure to be acknowledged", ex);
            } catch (TimeoutException ex) {
                throw new RuntimeException("Timed out while waiting for task failure to be acknowledged", ex);
            }
        }
    }

    @Override
    void abandon(final ActivityTask task) {
        try {
            // TODO: Retry on TimeoutException
            engine.abandonActivityTask(task).join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Interrupted while waiting for task abandonment to be acknowledged", e);
        } catch (TimeoutException e) {
            throw new RuntimeException("Timed out while waiting for task abandonment to be acknowledged", e);
        }
    }

}
