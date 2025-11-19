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
package org.dependencytrack.dex.engine.support;

import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public final class Buffer<T> implements Closeable {

    private enum Status {

        CREATED(1, 2), // 0
        RUNNING(2),    // 1
        STOPPING(3),   // 2
        STOPPED;       // 3

        private final Set<Integer> allowedTransitions;

        Status(final Integer... allowedTransitions) {
            this.allowedTransitions = Set.of(allowedTransitions);
        }

        private boolean canTransitionTo(final Status newStatus) {
            return allowedTransitions.contains(newStatus.ordinal());
        }

        private boolean isRunningOrStopping() {
            return equals(RUNNING) || equals(STOPPING);
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(Buffer.class);

    private record BufferedItem<I>(I item, CompletableFuture<@Nullable Void> future) {
    }

    private final String name;
    private final Consumer<List<T>> batchConsumer;
    private final int maxBatchSize;
    private final BlockingQueue<BufferedItem<T>> itemsQueue;
    private final Duration itemsQueueTimeout;
    private final List<BufferedItem<T>> currentBatch;
    private final ScheduledExecutorService flushExecutor;
    private final Duration flushInterval;
    private final ReentrantLock flushLock;
    private final ReentrantLock statusLock;
    private final MeterRegistry meterRegistry;
    private Status status = Status.CREATED;
    private @Nullable DistributionSummary batchSizeDistribution;
    private @Nullable Timer flushLatencyTimer;

    public Buffer(
            final String name,
            final Consumer<List<T>> batchConsumer,
            final Duration flushInterval,
            final int maxBatchSize,
            final MeterRegistry meterRegistry) {
        this(name, batchConsumer, flushInterval, maxBatchSize, Duration.ofSeconds(5), meterRegistry);
    }

    Buffer(
            final String name,
            final Consumer<List<T>> batchConsumer,
            final Duration flushInterval,
            final int maxBatchSize,
            final Duration itemsQueueTimeout,
            final MeterRegistry meterRegistry) {
        this.name = name;
        this.batchConsumer = batchConsumer;
        this.maxBatchSize = maxBatchSize;
        this.itemsQueue = new ArrayBlockingQueue<>(maxBatchSize);
        this.itemsQueueTimeout = itemsQueueTimeout;
        this.currentBatch = new ArrayList<>(maxBatchSize);
        this.flushExecutor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofVirtual().name("DexEngine-Buffer-" + name).factory());
        this.flushInterval = flushInterval;
        this.flushLock = new ReentrantLock();
        this.statusLock = new ReentrantLock();
        this.meterRegistry = meterRegistry;
    }

    public void start() {
        final List<Tag> commonMeterTags = List.of(Tag.of("buffer", name));
        batchSizeDistribution = DistributionSummary
                .builder("dt.dex.engine.buffer.flush.batch.size")
                .tags(commonMeterTags)
                .register(meterRegistry);
        flushLatencyTimer = Timer
                .builder("dt.dex.engine.buffer.flush.latency")
                .tags(commonMeterTags)
                .register(meterRegistry);
        new ExecutorServiceMetrics(flushExecutor, "dt.dex.engine.buffer.%s".formatted(name), null)
                .bindTo(meterRegistry);

        flushExecutor.scheduleAtFixedRate(
                () -> {
                    try {
                        maybeFlush();
                    } catch (RuntimeException e) {
                        LOGGER.error("Failed to flush buffer", e);
                    }
                },
                flushInterval.toMillis(),
                flushInterval.toMillis(),
                TimeUnit.MILLISECONDS);

        setStatus(Status.RUNNING);
    }

    @Override
    public void close() {
        LOGGER.debug("{}: Closing", name);
        setStatus(Status.STOPPING);

        LOGGER.debug("{}: Waiting for flush executor to stop", name);
        flushExecutor.close();
        setStatus(Status.STOPPED);

        // Flush one last time, in case new items were added to the buffer while
        // the executor was shutting down.
        maybeFlush();
    }

    public CompletableFuture<Void> add(final T item) throws InterruptedException, TimeoutException {
        if (!status.isRunningOrStopping()) {
            throw new IllegalStateException("Cannot accept new items in current status: " + status);
        }

        final CompletableFuture<Void> future = new CompletableFuture<>();
        final boolean added = itemsQueue.offer(
                new BufferedItem<>(item, future),
                itemsQueueTimeout.toMillis(),
                TimeUnit.MILLISECONDS);
        if (!added) {
            throw new TimeoutException("Timed out while waiting for buffer queue to accept the item");
        }

        // TODO: Flush NOW when capacity is reached?

        return future;
    }

    private void maybeFlush() {
        flushLock.lock();
        try {
            if (itemsQueue.isEmpty()) {
                LOGGER.debug("{}: Buffer is empty; Nothing to flush", name);
                return;
            }

            itemsQueue.drainTo(currentBatch, maxBatchSize);

            if (batchSizeDistribution != null) {
                batchSizeDistribution.record(currentBatch.size());
            }

            LOGGER.debug("{}: Flushing batch of {} items", name, currentBatch.size());
            final Timer.Sample flushLatencySample = Timer.start();
            try {
                batchConsumer.accept(currentBatch.stream().map(BufferedItem::item).collect(Collectors.toList()));
                for (final BufferedItem<T> bufferedItem : currentBatch) {
                    bufferedItem.future().complete(null);
                }
            } catch (Throwable e) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("{}: Flush of {} items failed", name, currentBatch.size(), e);
                }

                for (final BufferedItem<T> item : currentBatch) {
                    item.future().completeExceptionally(e);
                }
            } finally {
                if (flushLatencyTimer != null) {
                    final long latencyNanos = flushLatencySample.stop(flushLatencyTimer);
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("{}: Flush of {} items completed in {}",
                                name, currentBatch.size(), Duration.ofNanos(latencyNanos));
                    }
                }

                currentBatch.clear();
            }
        } finally {
            flushLock.unlock();
        }
    }

    private void setStatus(final Status newStatus) {
        statusLock.lock();
        try {
            if (this.status == newStatus) {
                return;
            }

            if (this.status.canTransitionTo(newStatus)) {
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
