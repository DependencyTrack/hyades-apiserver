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
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.dependencytrack.workflow.engine.support.LoggingUncaughtExceptionHandler;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

abstract class AbstractTaskWorker<T extends Task> implements TaskWorker {

    private final long minPollIntervalMillis;
    private final IntervalFunction pollBackoffIntervalFunction;
    private final Semaphore semaphore;
    private final MeterRegistry meterRegistry;
    private final Lock statusLock;
    final Logger logger;

    private volatile Status status = Status.CREATED;
    private @Nullable Thread pollThread;
    private @Nullable ExecutorService taskExecutor;
    private @Nullable Timer pollLatencyTimer;
    private @Nullable Counter pollsCounter;
    private @Nullable MeterProvider<DistributionSummary> polledTasksDistribution;
    private @Nullable MeterProvider<Counter> processedCounter;
    private @Nullable MeterProvider<Timer> processLatencyTimer;

    AbstractTaskWorker(
            final Duration minPollInterval,
            final IntervalFunction pollBackoffIntervalFunction,
            final int maxConcurrency,
            final MeterRegistry meterRegistry) {
        this.minPollIntervalMillis = requireNonNull(minPollInterval, "minPollInterval must not be null").toMillis();
        this.pollBackoffIntervalFunction = requireNonNull(pollBackoffIntervalFunction, "pollBackoffIntervalFunction must not be null");
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.statusLock = new ReentrantLock();
        this.semaphore = new Semaphore(maxConcurrency);
        this.logger = LoggerFactory.getLogger(getClass());
    }

    abstract List<T> poll(int limit);

    abstract void process(T task);

    abstract void abandon(T task);

    @Override
    public void start() {
        setStatus(Status.STARTING);

        pollThread = Thread.ofVirtual()
                .name("%s-Poller".formatted(getClass().getSimpleName()), 0)
                .uncaughtExceptionHandler(new LoggingUncaughtExceptionHandler())
                .unstarted(this::pollAndDispatch);

        final var taskExecutorName = "%s-Executor".formatted(getClass().getSimpleName());
        taskExecutor = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .uncaughtExceptionHandler(new LoggingUncaughtExceptionHandler())
                        .name(taskExecutorName, 0)
                        .factory());

        new ExecutorServiceMetrics(taskExecutor, taskExecutorName, null).bindTo(meterRegistry);

        final var commonMeterTags = List.of(Tag.of("workerType", getClass().getSimpleName()));
        pollLatencyTimer = Timer
                .builder("dt.workflow.engine.task.worker.poll.latency")
                .tags(commonMeterTags)
                .register(meterRegistry);
        pollsCounter = Counter
                .builder("dt.workflow.engine.task.worker.polls")
                .tags(commonMeterTags)
                .register(meterRegistry);
        polledTasksDistribution = DistributionSummary
                .builder("dt.workflow.engine.task.worker.tasks.polled")
                .tags(commonMeterTags)
                .withRegistry(meterRegistry);
        processedCounter = Counter
                .builder("dt.workflow.engine.task.worker.tasks.processed")
                .tags(commonMeterTags)
                .withRegistry(meterRegistry);
        processLatencyTimer = Timer
                .builder("dt.workflow.engine.task.worker.process.latency")
                .tags(commonMeterTags)
                .withRegistry(meterRegistry);

        pollThread.start();

        setStatus(Status.RUNNING);
    }

    @Override
    public Status status() {
        return status;
    }

    @Override
    public void close() {
        setStatus(Status.STOPPING);

        if (pollThread != null) {
            logger.debug("Waiting for poll thread to stop");
            try {
                final boolean terminated = pollThread.join(Duration.ofSeconds(10));
                if (!terminated) {
                    pollThread.interrupt();
                }
            } catch (InterruptedException e) {
                logger.warn("Interrupted waiting for poll thread to stop", e);
                Thread.currentThread().interrupt();
            }
        }
        if (taskExecutor != null) {
            logger.debug("Waiting for task executor to stop");
            taskExecutor.close();
            taskExecutor = null;
        }

        setStatus(Status.STOPPED);
    }

    private void pollAndDispatch() {
        long nowMillis;
        long lastPolledAtMillis = 0;
        long nextPollAtMillis;
        long nextPollDueInMillis;
        int pollsWithoutResults = 0;

        while (!status.isStoppingOrStopped() && !Thread.currentThread().isInterrupted()) {
            if (pollsWithoutResults == 0) {
                nowMillis = System.currentTimeMillis();
                nextPollAtMillis = lastPolledAtMillis + minPollIntervalMillis;
                nextPollDueInMillis = nextPollAtMillis > nowMillis
                        ? nextPollAtMillis - nowMillis
                        : 0;
            } else {
                nextPollDueInMillis = pollBackoffIntervalFunction.apply(pollsWithoutResults);
            }

            try {
                Thread.sleep(nextPollDueInMillis);
            } catch (InterruptedException e) {
                logger.info("Interrupted while waiting for next poll to be due", e);
                Thread.currentThread().interrupt();
                break;
            }

            try {
                final boolean acquired = semaphore.tryAcquire(5, TimeUnit.SECONDS);
                if (!acquired) {
                    logger.debug("All task executors busy, nothing to poll");
                    continue;
                }

                semaphore.release();
            } catch (InterruptedException e) {
                logger.debug("Interrupted while waiting for available task executors", e);
                Thread.currentThread().interrupt();
                break;
            }

            final int tasksToPoll = semaphore.availablePermits();
            assert tasksToPoll > 0;

            logger.debug("Polling for up to {} tasks", tasksToPoll);
            pollsCounter.increment();

            final List<T> polledTasks;
            final Timer.Sample pollLatencySample = Timer.start();
            try {
                polledTasks = poll(tasksToPoll);
            } finally {
                pollLatencySample.stop(pollLatencyTimer);
            }

            if (polledTasks.isEmpty()) {
                pollsWithoutResults++;
                continue;
            }

            pollsWithoutResults = 0;

            final Map<Set<Tag>, Long> taskCountByMeterTags =
                    polledTasks.stream().collect(
                            Collectors.groupingBy(
                                    Task::meterTags,
                                    Collectors.counting()));
            for (final Map.Entry<Set<Tag>, Long> entry : taskCountByMeterTags.entrySet()) {
                polledTasksDistribution
                        .withTags(entry.getKey())
                        .record(entry.getValue());
            }

            final var permitAcquiredLatch = new CountDownLatch(polledTasks.size());
            final var submittedFutures = new ArrayList<Future<?>>(polledTasks.size());

            for (final T polledTask : polledTasks) {
                submittedFutures.add(
                        taskExecutor.submit(
                                () -> executeTask(polledTask, permitAcquiredLatch)));
            }

            try {
                // Prevent race conditions where the next poll iteration acquires a semaphore
                // permit before the task executors acquired theirs.
                permitAcquiredLatch.await();
            } catch (InterruptedException e) {
                logger.warn("Interrupted while waiting for task executors to start", e);
                submittedFutures.forEach(future -> future.cancel(/* interruptIfRunning */ true));
                Thread.currentThread().interrupt();
            }
        }
    }

    private void executeTask(final T task, final CountDownLatch permitAcquiredLatch) {
        boolean permitAcquired = false;

        try {
            semaphore.acquire();
            permitAcquired = true;
            permitAcquiredLatch.countDown();

            final Timer.Sample processLatencySample = Timer.start();
            try {
                process(task);

                processedCounter
                        .withTags(task.meterTags())
                        .increment();
            } finally {
                processLatencySample.stop(
                        processLatencyTimer.withTags(task.meterTags()));
            }
        } catch (InterruptedException e) {
            logger.warn("Interrupted while waiting for semaphore permit", e);
            Thread.currentThread().interrupt();
        } finally {
            if (permitAcquired) {
                semaphore.release();
            } else {
                permitAcquiredLatch.countDown();
            }
        }
    }

    private void setStatus(final Status newStatus) {
        statusLock.lock();
        try {
            if (this.status == newStatus) {
                return;
            }

            if (this.status.canTransitionTo(newStatus)) {
                logger.debug("Transitioning from status {} to {}", this.status, newStatus);
                this.status = newStatus;
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from status %s to %s".formatted(this.status, newStatus));
        } finally {
            statusLock.unlock();
        }
    }

}
