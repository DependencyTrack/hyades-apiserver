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

import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
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

final class Buffer<T> implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Buffer.class);

    private record BufferedItem<I>(I item, CompletableFuture<Void> future) {
    }

    private final String name;
    private final Consumer<List<T>> batchConsumer;
    private final int maxBatchSize;
    private final BlockingQueue<BufferedItem<T>> bufferedItems;
    private final List<BufferedItem<T>> currentBatch;
    private final ScheduledExecutorService flushExecutor;
    private final Duration flushInterval;
    private final ReentrantLock flushLock;
    private final MeterRegistry meterRegistry;
    private DistributionSummary batchSizeDistribution;
    private Timer flushLatencyTimer;

    Buffer(
            final String name,
            final Consumer<List<T>> batchConsumer,
            final Duration flushInterval,
            final int maxBatchSize,
            final MeterRegistry meterRegistry) {
        this.name = name;
        this.batchConsumer = batchConsumer;
        this.maxBatchSize = maxBatchSize;
        this.bufferedItems = new ArrayBlockingQueue<>(maxBatchSize);
        this.currentBatch = new ArrayList<>(maxBatchSize);
        this.flushExecutor = Executors.newSingleThreadScheduledExecutor();
        this.flushInterval = flushInterval;
        this.flushLock = new ReentrantLock();
        this.meterRegistry = meterRegistry;
    }

    public void start() {
        maybeInitializeMeters();

        flushExecutor.scheduleAtFixedRate(
                this::maybeFlush,
                flushInterval.toMillis(),
                flushInterval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        LOGGER.debug("{}: Closing", name);

        LOGGER.debug("{}: Waiting for flush executor to stop", name);
        flushExecutor.close();

        // Flush one last time, in case new items were added to the buffer while
        // the executor was shutting down.
        maybeFlush();
    }

    public CompletableFuture<Void> add(final T item) throws InterruptedException, TimeoutException {
        final CompletableFuture<Void> future = new CompletableFuture<>();
        final boolean added = bufferedItems.offer(
                new BufferedItem<>(item, future), 5, TimeUnit.SECONDS);
        if (!added) {
            throw new TimeoutException("Timed out while waiting for buffer queue to accept the item");
        }

        // TODO: Flush NOW when capacity is reached?

        return future;
    }

    private void maybeFlush() {
        flushLock.lock();
        try {
            if (bufferedItems.isEmpty()) {
                LOGGER.debug("{}: Buffer is empty; Nothing to flush", name);
                return;
            }

            bufferedItems.drainTo(currentBatch, maxBatchSize);

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
                if (LOGGER.isTraceEnabled()) {
                    LOGGER.trace("{}: Flush of {} items failed", name, currentBatch.size(), e);
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

    private void maybeInitializeMeters() {
        if (meterRegistry == null) {
            return;
        }

        final List<Tag> commonTags = List.of(Tag.of("buffer", name));

        batchSizeDistribution = DistributionSummary
                .builder("dtrack.buffer.flush.batch.size")
                .tags(commonTags)
                .register(meterRegistry);

        flushLatencyTimer = Timer
                .builder("dtrack.buffer.flush.latency")
                .tags(commonTags)
                .register(meterRegistry);

        new ExecutorServiceMetrics(flushExecutor, "dtrack.buffer.%s".formatted(name), null)
                .bindTo(meterRegistry);
    }

}
