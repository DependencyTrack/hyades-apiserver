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
package org.dependencytrack.job;

import alpine.common.logging.Logger;
import io.github.resilience4j.core.IntervalFunction;
import org.slf4j.MDC;

import java.io.Closeable;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class JobManager implements Closeable {

    private static final Logger LOGGER = Logger.getLogger(JobManager.class);
    private static final JobManager INSTANCE = new JobManager();

    private final Map<String, ExecutorService> executorByTag = new ConcurrentHashMap<>();
    private final AtomicBoolean isShuttingDown = new AtomicBoolean(false);

    public static JobManager getInstance() {
        return INSTANCE;
    }

    public void tearDown() throws Exception {
        close();
    }

    public void registerWorker(final Set<String> tags, final JobWorker worker, final int concurrency) {
        if (isShuttingDown.get()) {
            throw new IllegalStateException();
        }

        final boolean isCloseable = Closeable.class.isAssignableFrom(worker.getClass());
        final int numThreads = isCloseable ? concurrency + 1 : concurrency;
        final ExecutorService es = Executors.newFixedThreadPool(numThreads);
        executorByTag.put(worker.getClass().getName(), es);
        final var intervalFunction = IntervalFunction.ofExponentialRandomBackoff(
                /* initialIntervalMillis */ 250,
                /* multiplier */ 1.5,
                /* randomizationFactor */ 0.3,
                /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(5));

        final var workersLatch = new CountDownLatch(concurrency);
        for (int i = 0; i < concurrency; i++) {
            final var workerThreadId = UUID.randomUUID();
            es.submit(() -> {
                try (var ignoredMdcJobWorker = MDC.putCloseable("jobWorker", worker.getClass().getName());
                     var ignoredMdcJobWorkerThreadId = MDC.putCloseable("jobWorkerThread", workerThreadId.toString())) {
                    final var pollMisses = new AtomicInteger(0);
                    while (!isShuttingDown.get()) {
                        final QueuedJob polledJob = inJdbiTransaction(handle -> handle.attach(JobDao.class).poll(tags));
                        if (polledJob == null) {
                            final long backoffMs = intervalFunction.apply(pollMisses.incrementAndGet());
                            LOGGER.info("Backing off for %dms".formatted(backoffMs));
                            try {
                                Thread.sleep(backoffMs);
                                continue;
                            } catch (InterruptedException e) {
                                throw new RuntimeException(e);
                            }
                        }

                        pollMisses.set(0);
                        try (var ignoredMdcJobId = MDC.putCloseable("jobId", String.valueOf(polledJob.id()));
                             var ignoredMdcJobPriority = MDC.putCloseable("jobPriority", String.valueOf(polledJob.priority()));
                             var ignoredMdcJobAttempts = MDC.putCloseable("jobAttempts", String.valueOf(polledJob.attempts()))) {
                            worker.process(polledJob);
                            useJdbiTransaction(handle -> handle.attach(JobDao.class).complete(polledJob));
                            LOGGER.info("Job completed successfully");
                        } catch (RuntimeException e) {
                            LOGGER.error("Job processing failed", e);
                            useJdbiTransaction(handle -> handle.attach(JobDao.class).fail(polledJob));
                        }
                    }
                } catch (RuntimeException e) {
                    LOGGER.error("F", e);
                } finally {
                    workersLatch.countDown();
                }
            });
        }

        if (isCloseable) {
            es.submit(() -> {
                try {
                    workersLatch.await();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }

                try (var ignoredMdcJobWorker = MDC.putCloseable("jobWorker", worker.getClass().getName())) {
                    final var closeable = (Closeable) worker;
                    closeable.close();
                } catch (IOException | RuntimeException e) {
                    LOGGER.error("Failed to close worker", e);
                }
            });
        }
    }

    @Override
    public void close() throws IOException {
        LOGGER.info("Signaling workers to shut down");
        isShuttingDown.set(true);

        LOGGER.info("Waiting for workers to complete shutdown");
        for (final Map.Entry<String, ExecutorService> entry : executorByTag.entrySet()) {
            final String tag = entry.getKey();
            final ExecutorService executorService = entry.getValue();

            executorService.shutdown();
            try {
                final boolean terminated = executorService.awaitTermination(30, TimeUnit.SECONDS);
                if (!terminated) {
                    LOGGER.warn("Executor for tag %s did not terminate".formatted(tag));
                }
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        executorByTag.clear();
        isShuttingDown.set(false);
    }

}
