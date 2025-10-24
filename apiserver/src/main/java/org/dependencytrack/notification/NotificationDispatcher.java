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
package org.dependencytrack.notification;

import alpine.event.framework.LoggableUncaughtExceptionHandler;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.jdbi.NotificationOutboxDao;
import org.dependencytrack.proto.notification.v1.Notification;
import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.ModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * Dispatcher of notifications.
 *
 * @since 5.7.0
 */
public final class NotificationDispatcher implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationDispatcher.class);
    private static final long ADVISORY_LOCK_ID = 275439834778508297L;
    private static final String EXECUTOR_NAME = "NotificationDispatcher";

    private final KafkaEventDispatcher delegateDispatcher;
    private final MeterRegistry meterRegistry;
    private final long pollIntervalMillis;
    private final int batchSize;
    private ScheduledExecutorService executorService;
    private Timer dispatchLatencyTimer;
    private Timer pollLatencyTimer;
    private MeterProvider<DistributionSummary> dispatchedDistribution;

    public NotificationDispatcher(
            final KafkaEventDispatcher delegateDispatcher,
            final MeterRegistry meterRegistry,
            final long pollIntervalMillis,
            final int batchSize) {
        this.delegateDispatcher = requireNonNull(delegateDispatcher, "delegate dispatcher must not be null");
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.pollIntervalMillis = pollIntervalMillis;
        this.batchSize = batchSize;
    }

    public void start() {
        // Obviously this check isn't thread safe, but we expect this
        // method to only be called once on startup.
        if (executorService != null) {
            throw new IllegalStateException("Already started");
        }

        executorService = Executors.newSingleThreadScheduledExecutor(
                BasicThreadFactory.builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern(EXECUTOR_NAME + "-%d")
                        .build());
        new ExecutorServiceMetrics(executorService, EXECUTOR_NAME, null)
                .bindTo(meterRegistry);

        dispatchLatencyTimer = Timer
                .builder("dtrack.notifications.dispatch.latency")
                .description("Latency of notification dispatches")
                .register(meterRegistry);

        pollLatencyTimer = Timer
                .builder("dtrack.notifications.poll.latency")
                .description("Latency of polls from the notification outbox")
                .register(meterRegistry);

        dispatchedDistribution = DistributionSummary
                .builder("dtrack.notifications.dispatched")
                .description("Number of dispatched notifications")
                .withRegistry(meterRegistry);

        executorService.scheduleWithFixedDelay(
                this::pollAndDispatch,
                0,
                pollIntervalMillis,
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (executorService != null) {
            executorService.close();
            executorService = null;
        }
    }

    private void pollAndDispatch() {
        useJdbiTransaction(handle -> {
            // Acquire advisory lock to prevent concurrent dispatching from multiple instances.
            //
            // Ideally we want dispatches to happen in the order in which notifications were
            // emitted. Work-stealing polling with FOR UPDATE SKIP LOCKED would mess with ordering.
            //
            // The lack of concurrency is in part mitigated by processing notifications in batches.
            final boolean lockAcquired = tryAcquireAdvisoryLock(handle);
            if (!lockAcquired) {
                LOGGER.debug("Lock already acquired by another instance");
                return;
            }

            final Timer.Sample dispatchLatencySample = Timer.start();

            final var outboxDao = handle.attach(NotificationOutboxDao.class);

            final Timer.Sample pollLatencySample = Timer.start();
            final List<Notification> notifications = outboxDao.poll(batchSize);
            final long pollLatencyNanos = pollLatencySample.stop(pollLatencyTimer);
            LOGGER.debug(
                    "Poll returned {} notifications in {}ms",
                    notifications.size(),
                    TimeUnit.NANOSECONDS.toMillis(pollLatencyNanos));

            if (notifications.isEmpty()) {
                return;
            }

            dispatchAll(notifications);

            for (final Notification notification : notifications) {
                dispatchedDistribution
                        .withTags(List.of(
                                Tag.of("level", convert(notification.getLevel()).name()),
                                Tag.of("scope", convert(notification.getScope()).name()),
                                Tag.of("group", convert(notification.getGroup()).name())))
                        .record(1);
            }

            final long dispatchLatencyNanos = dispatchLatencySample.stop(dispatchLatencyTimer);
            LOGGER.debug(
                    "Dispatch of {} notifications completed in {}ms",
                    notifications.size(),
                    TimeUnit.NANOSECONDS.toMillis(dispatchLatencyNanos));
        });
    }

    private boolean tryAcquireAdvisoryLock(final Handle handle) {
        return handle.createQuery("""
                        SELECT pg_try_advisory_xact_lock(:lockId)
                        """)
                .bind("lockId", ADVISORY_LOCK_ID)
                .mapTo(boolean.class)
                .one();
    }

    private void dispatchAll(final Collection<Notification> notifications) {
        final List<CompletableFuture<RecordMetadata>> futures =
                delegateDispatcher.dispatchAllNotificationProtos(notifications);

        final CompletableFuture<?> combinedFuture =
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));

        try {
            // Since we're in a database transaction, ensure we're not blocking it
            // for prolonged time. 5 seconds should be plenty for every Kafka cluster.
            combinedFuture.get(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Interrupted while waiting for notifications to be dispatched", e);
        } catch (TimeoutException e) {
            throw new IllegalStateException(
                    "Timed out while waiting for notifications to be dispatched", e);
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failed to dispatch notifications", e.getCause());
        }
    }

}
