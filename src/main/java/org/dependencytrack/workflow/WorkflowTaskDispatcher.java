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

import alpine.common.metrics.Metrics;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

final class WorkflowTaskDispatcher<T extends WorkflowTask> implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowTaskDispatcher.class);
    private static final IntervalFunction POLL_BACKOFF_INTERVAL_FUNCTION =
            IntervalFunction.ofExponentialRandomBackoff(
                    /* initialIntervalMillis */ 500,
                    /* multiplier */ 1.5,
                    /* randomizationFactor */ 0.3,
                    /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(5));

    private final WorkflowEngine engine;
    private final ExecutorService taskExecutorService;
    private final WorkflowTaskProcessor<T> taskProcessor;
    private final Semaphore taskSemaphore;

    WorkflowTaskDispatcher(
            final WorkflowEngine engine,
            final ExecutorService taskExecutorService,
            final WorkflowTaskProcessor<T> taskProcessor,
            final int maxConcurrency) {
        this.engine = engine;
        this.taskExecutorService = taskExecutorService;
        this.taskProcessor = taskProcessor;
        this.taskSemaphore = new Semaphore(maxConcurrency);
    }

    @Override
    public void run() {
        int pollsWithoutResults = 0;

        while (engine.state().isNotStoppingOrStopped() && !Thread.currentThread().isInterrupted()) {
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
            final List<T> polledTasks;
            final Timer.Sample pollTimerSample = Timer.start();
            try {
                polledTasks = taskProcessor.poll(tasksToPoll);
            } finally {
                pollTimerSample.stop(Timer
                        .builder("dtrack.workflow.task.dispatcher.poll.latency")
                        .tag("taskType", switch (taskProcessor) {
                            case ActivityRunTaskProcessor<?, ?> ignored -> "activity";
                            case WorkflowRunTaskProcessor<?, ?> ignored -> "workflow";
                        })
                        .register(Metrics.getRegistry()));
            }

            DistributionSummary
                    .builder("dtrack.workflow.task.dispatcher.poll.tasks")
                    .tag("taskType", switch (taskProcessor) {
                        case ActivityRunTaskProcessor<?, ?> ignored -> "activity";
                        case WorkflowRunTaskProcessor<?, ?> ignored -> "workflow";
                    })
                    .register(Metrics.getRegistry())
                    .record(polledTasks.size());

            if (polledTasks.isEmpty()) {
                final long backoffMs = POLL_BACKOFF_INTERVAL_FUNCTION.apply(++pollsWithoutResults);
                LOGGER.debug("Backing off for {}ms", backoffMs);
                try {
                    //noinspection BusyWait
                    Thread.sleep(backoffMs);
                    continue;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.warn("Thread interrupted during poll backoff", e);
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

    private void executeTask(final T polledTask, final CountDownLatch permitAcquiredLatch) {
        try {
            taskSemaphore.acquire();
            permitAcquiredLatch.countDown();

            final Timer.Sample taskProcessingTimerSample = Timer.start();
            try {
                taskProcessor.process(polledTask);
            } finally {
                taskProcessingTimerSample.stop(Timer.builder("dtrack.workflow.task.process.latency")
                        .tag("taskType", switch (taskProcessor) {
                            case ActivityRunTaskProcessor<?, ?> ignored -> "activity";
                            case WorkflowRunTaskProcessor<?, ?> ignored -> "workflow";
                        })
                        .register(Metrics.getRegistry()));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for semaphore permit", e);
            taskProcessor.abandon(polledTask);
        } finally {
            taskSemaphore.release();
        }
    }

}