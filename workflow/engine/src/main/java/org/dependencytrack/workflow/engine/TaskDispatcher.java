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

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

final class TaskDispatcher<T extends Task> implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskDispatcher.class);

    private final WorkflowEngineImpl engine;
    private final ExecutorService taskExecutorService;
    private final TaskManager<T> taskManager;
    private final Semaphore taskSemaphore;
    @Nullable private final Duration minPollInterval;
    @Nullable private final IntervalFunction pollBackoffIntervalFunction;
    @Nullable private final MeterRegistry meterRegistry;
    @Nullable private Instant lastPolledAt;
    @Nullable private Timer taskPollLatencyTimer;
    @Nullable private Counter taskPollsCounter;
    @Nullable private MeterProvider<DistributionSummary> taskPollDistributionProvider;
    @Nullable private MeterProvider<Counter> tasksProcessedCounterProvider;
    @Nullable private MeterProvider<Timer> taskProcessLatencyTimerProvider;

    TaskDispatcher(
            final WorkflowEngineImpl engine,
            final ExecutorService taskExecutorService,
            final TaskManager<T> taskManager,
            final int maxConcurrency,
            @Nullable final Duration minPollInterval,
            @Nullable final IntervalFunction pollBackoffIntervalFunction,
            @Nullable final MeterRegistry meterRegistry) {
        this.engine = engine;
        this.taskExecutorService = taskExecutorService;
        this.taskManager = taskManager;
        this.taskSemaphore = new Semaphore(maxConcurrency);
        this.minPollInterval = minPollInterval;
        this.pollBackoffIntervalFunction = pollBackoffIntervalFunction;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void run() {
        maybeInitializeMeters();

        int pollsWithoutResults = 0;

        while (engine.status().isNotStoppingOrStopped() && !Thread.currentThread().isInterrupted()) {
            final boolean interruptedDuringSleep = maybeSleepUntilNextPollIsDue();
            if (interruptedDuringSleep) {
                break;
            }

            // Attempt to acquire a permit from the semaphore, blocking for up to 5 seconds.
            // If acquisition was successful, immediately release the permit again.
            // This is a poor-man's alternative to busy-waiting on taskSemaphore.availablePermits() > 0.
            try {
                boolean acquired = taskSemaphore.tryAcquire(5, TimeUnit.SECONDS);
                if (!acquired) {
                    LOGGER.debug("All task executors busy, nothing to poll");
                    pollsWithoutResults = 0; // Already waited longer than the max poll backoff.
                    continue;
                }

                taskSemaphore.release();
            } catch (InterruptedException e) {
                LOGGER.info("Interrupted while waiting for available executors");
                Thread.currentThread().interrupt();
                break;
            }

            final int tasksToPoll = taskSemaphore.availablePermits();
            assert tasksToPoll > 0;

            LOGGER.debug("Polling up to {} tasks", tasksToPoll);
            if (taskPollsCounter != null) {
                taskPollsCounter.increment();
            }

            final List<T> polledTasks;
            final Timer.Sample taskPollLatencySample = Timer.start();
            try {
                polledTasks = taskManager.poll(tasksToPoll);
                lastPolledAt = Instant.now();
            } finally {
                if (taskPollLatencyTimer != null) {
                    taskPollLatencySample.stop(taskPollLatencyTimer);
                }
            }

            if (taskPollDistributionProvider != null) {
                final Map<Set<Tag>, Long> taskCountByMeterTags =
                        polledTasks.stream()
                                .collect(Collectors.groupingBy(
                                        Task::meterTags,
                                        Collectors.counting()));
                for (final Map.Entry<Set<Tag>, Long> entry : taskCountByMeterTags.entrySet()) {
                    taskPollDistributionProvider
                            .withTags(entry.getKey())
                            .record(entry.getValue());
                }
            }

            if (polledTasks.isEmpty()) {
                if (pollBackoffIntervalFunction == null) {
                    continue;
                }

                final long backoffMillis = pollBackoffIntervalFunction.apply(++pollsWithoutResults);
                LOGGER.debug("Backing off for {}ms", backoffMillis);
                try {
                    //noinspection BusyWait
                    Thread.sleep(backoffMillis);
                    continue;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.warn("Interrupted during poll backoff", e);
                    break;
                }
            }

            pollsWithoutResults = 0;

            // Prevent race conditions where the next dispatcher iteration acquires a semaphore
            // permit before the dispatched tasks acquired theirs.
            final var permitAcquiredLatch = new CountDownLatch(polledTasks.size());
            for (final T polledTask : polledTasks) {
                taskExecutorService.execute(() -> executeTask(polledTask, permitAcquiredLatch));
            }

            try {
                permitAcquiredLatch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.warn("Interrupted while waiting for task executors to start", e);
            }
        }
    }

    private void executeTask(final T task, final CountDownLatch permitAcquiredLatch) {
        try {
            taskSemaphore.acquire();
            permitAcquiredLatch.countDown();

            final Timer.Sample taskProcessingLatencySample = Timer.start();
            try {
                taskManager.process(task);

                if (tasksProcessedCounterProvider != null) {
                    tasksProcessedCounterProvider
                            .withTags(task.meterTags())
                            .increment();
                }
            } finally {
                if (taskProcessLatencyTimerProvider != null) {
                    taskProcessingLatencySample.stop(
                            taskProcessLatencyTimerProvider
                                    .withTags(task.meterTags()));
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for semaphore permit", e);
            taskManager.abandon(task);
        } finally {
            taskSemaphore.release();
        }
    }

    private boolean maybeSleepUntilNextPollIsDue() {
        if (lastPolledAt == null || minPollInterval == null || minPollInterval.isZero()) {
            return false;
        }

        final Instant now = Instant.now();
        final Instant nextPollAt = lastPolledAt.plus(minPollInterval);
        if (now.isAfter(nextPollAt)) {
            return false;
        }

        final Duration nextPollDueIn = Duration.between(now, nextPollAt);
        try {
            Thread.sleep(nextPollDueIn.toMillis());
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for next poll at {}", nextPollAt, e);
            return true;
        }

        return false;
    }

    private void maybeInitializeMeters() {
        if (meterRegistry == null) {
            return;
        }

        final List<Tag> commonTags = List.of(
                Tag.of("taskManager", taskManager.name()),
                Tag.of("taskType", switch (taskManager) {
                    case ActivityTaskManager ignored -> "activity";
                    case WorkflowTaskManager ignored -> "workflow";
                }));

        taskPollsCounter = Counter
                .builder("dtrack.workflow.engine.task.polls")
                .tags(commonTags)
                .register(meterRegistry);

        taskPollLatencyTimer = Timer
                .builder("dtrack.workflow.engine.task.dispatcher.poll.latency")
                .tags(commonTags)
                .register(meterRegistry);

        taskPollDistributionProvider = DistributionSummary
                .builder("dtrack.workflow.engine.task.dispatcher.poll.tasks")
                .tags(commonTags)
                .withRegistry(meterRegistry);

        tasksProcessedCounterProvider = Counter
                .builder("dtrack.workflow.engine.tasks.processed")
                .tags(commonTags)
                .withRegistry(meterRegistry);

        taskProcessLatencyTimerProvider = Timer
                .builder("dtrack.workflow.engine.task.process.latency")
                .tags(commonTags)
                .withRegistry(meterRegistry);
    }

}