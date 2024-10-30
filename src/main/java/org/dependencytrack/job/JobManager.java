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
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import io.github.resilience4j.core.IntervalFunction;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.dependencytrack.job.JobDao.JobStatusTransition;
import org.dependencytrack.job.JobEvent.JobCompletedEvent;
import org.dependencytrack.job.JobEvent.JobFailedEvent;
import org.dependencytrack.job.JobEvent.JobQueuedEvent;
import org.dependencytrack.job.JobEvent.JobStartedEvent;
import org.slf4j.MDC;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

// TODO: Metrics instrumentation
public class JobManager implements Closeable {

    private static final Logger LOGGER = Logger.getLogger(JobManager.class);
    private static final JobManager INSTANCE = new JobManager();

    private final BlockingQueue<JobEvent> eventQueue;
    private final ScheduledExecutorService eventFlushExecutor;
    private final ReentrantLock eventFlushLock = new ReentrantLock();
    private final Map<String, ExecutorService> executorByTag = new ConcurrentHashMap<>();
    private final List<JobEventListener> statusListeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean isShuttingDown = new AtomicBoolean(false);

    public JobManager() {
        this(100, Duration.ofSeconds(1), Duration.ofSeconds(3));
    }

    public JobManager(
            final int eventQueueSize,
            final Duration initialEventFlushDelay,
            final Duration eventFlushInterval) {
        // TODO: Move this to a start() method and make sure the engine can be restarted if stopped.
        // TODO: Find reasonable defaults for queue size and flush interval.
        this.eventQueue = new ArrayBlockingQueue<>(eventQueueSize);
        this.eventFlushExecutor = Executors.newSingleThreadScheduledExecutor(new BasicThreadFactory.Builder()
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .namingPattern("JobManager-EventFlusher-%d")
                .build());
        this.eventFlushExecutor.scheduleAtFixedRate(
                this::flushEvents,
                initialEventFlushDelay.toMillis(),
                eventFlushInterval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    public static JobManager getInstance() {
        return INSTANCE;
    }

    public void registerStatusListener(final JobEventListener listener) {
        statusListeners.add(listener);
    }

    public void registerWorker(final Set<String> tags, final int concurrency, final JobWorker worker) {
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
                            LOGGER.debug("Backing off for %dms".formatted(backoffMs));
                            try {
                                Thread.sleep(backoffMs);
                                continue;
                            } catch (InterruptedException e) {
                                throw new RuntimeException(e);
                            }
                        }

                        pollMisses.set(0);
                        notifyEventListeners(new JobStartedEvent(Instant.now(), polledJob));

                        try (var ignoredMdcJobId = MDC.putCloseable("jobId", String.valueOf(polledJob.id()));
                             var ignoredMdcJobTag = MDC.putCloseable("jobTag", polledJob.tag());
                             var ignoredMdcJobPriority = MDC.putCloseable("jobPriority", String.valueOf(polledJob.priority()));
                             var ignoredMdcJobAttempts = MDC.putCloseable("jobAttempts", String.valueOf(polledJob.attempts()))) {
                            worker.process(polledJob);
                            final var event = new JobCompletedEvent(Instant.now(), polledJob);
                            try {
                                eventQueue.put(event);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                throw new IllegalStateException("Failed to enqueue %s".formatted(event), e);
                            }
                            LOGGER.debug("Job completed successfully");
                        } catch (Exception e) {
                            // TODO: Retryable or fatal?
                            LOGGER.error("Job processing failed", e);
                            final var event = new JobFailedEvent(Instant.now(), polledJob, e.getMessage());
                            try {
                                eventQueue.put(event);
                            } catch (InterruptedException ex) {
                                Thread.currentThread().interrupt();
                                throw new IllegalStateException("Failed to enqueue %s".formatted(event), ex);
                            }
                        }
                    }
                } catch (RuntimeException e) {
                    // TODO: Potentially need to check if job needs to be failed.
                    //  Better yet, organize try-catch-blocks to make this less ambiguous.
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

    public List<QueuedJob> enqueueAll(final Collection<NewJob> newJobs) {
        final List<QueuedJob> queuedJobs = inJdbiTransaction(handle -> handle.attach(JobDao.class).enqueueAll(newJobs));

        // TODO: Notify in separate thread?
        for (final QueuedJob queuedJob : queuedJobs) {
            notifyEventListeners(new JobQueuedEvent(queuedJob.createdAt(), queuedJob));
        }

        return queuedJobs;
    }

    public QueuedJob enqueue(final NewJob newJob) {
        final List<QueuedJob> queuedJobs = enqueueAll(List.of(newJob));
        if (queuedJobs.size() != 1) {
            throw new IllegalStateException("Job was not queued");
        }

        return queuedJobs.getFirst();
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

        eventFlushExecutor.shutdown();
        try {
            final boolean terminated = eventFlushExecutor.awaitTermination(30, TimeUnit.SECONDS);
            if (!terminated) {
                LOGGER.warn("Flush executor did not terminate");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        flushEvents();
        eventQueue.clear();
        executorByTag.clear();
        statusListeners.clear();
        isShuttingDown.set(false);
    }

    private void flushEvents() {
        eventFlushLock.lock();
        try {
            flushEventsLocked();
        } finally {
            eventFlushLock.unlock();
        }
    }

    private void flushEventsLocked() {
        assert eventFlushLock.isLocked();

        if (eventQueue.isEmpty()) {
            LOGGER.debug("No events to flush");
            return;
        }

        final var eventsByStatus = new HashMap<JobStatus, List<JobEvent>>();
        while (eventQueue.peek() != null) {
            final JobEvent event = eventQueue.poll();
            final JobStatus status = switch (event) {
                case JobCompletedEvent ignored -> JobStatus.COMPLETED;
                case JobFailedEvent ignored -> JobStatus.FAILED;
                default -> throw new IllegalStateException("Unexpected event: " + event);
            };

            eventsByStatus.compute(status, (ignored, events) -> {
                if (events == null) {
                    return new ArrayList<>(List.of(event));
                }

                events.add(event);
                return events;
            });
        }

        final var completedJobs = new ArrayList<QueuedJob>();
        final var failedJobs = new ArrayList<QueuedJob>();
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(JobDao.class);

            final List<JobEvent> completedEvents = eventsByStatus.get(JobStatus.COMPLETED);
            if (completedEvents != null) {
                completedJobs.addAll(dao.transitionStatus(completedEvents.stream()
                        .map(event -> new JobStatusTransition(
                                event.job().id(),
                                JobStatus.COMPLETED,
                                /* failureReason */ null,
                                event.timestamp()))
                        .toList()));
            }

            final List<JobEvent> failedEvents = eventsByStatus.get(JobStatus.FAILED);
            if (failedEvents != null) {
                failedJobs.addAll(dao.transitionStatus(failedEvents.stream()
                        .map(event -> new JobStatusTransition(
                                event.job().id(),
                                JobStatus.FAILED,
                                ((JobFailedEvent) event).failureReason(),
                                event.timestamp()))
                        .toList()));
            }
        });

        if (LOGGER.isDebugEnabled()) {
            for (final QueuedJob completedJob : completedJobs) {
                LOGGER.debug("Completed %s".formatted(completedJob));
            }
        }
        for (final QueuedJob failedJob : failedJobs) {
            LOGGER.warn("Failed %s".formatted(failedJob));
        }

        Stream.concat(completedJobs.stream(), failedJobs.stream())
                .sorted(Comparator.comparing(QueuedJob::updatedAt))
                .map(job -> switch (job.status()) {
                    case COMPLETED -> new JobCompletedEvent(job.updatedAt(), job);
                    case FAILED -> new JobFailedEvent(job.updatedAt(), job, job.failureReason());
                    default -> throw new IllegalStateException("Unexpected job status: " + job.status());
                })
                .forEach(this::notifyEventListeners);
    }

    private void notifyEventListeners(final JobEvent event) {
        for (final JobEventListener listener : statusListeners) {
            try {
                listener.onJobEvent(event);
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to notify listener %s for event: %s".formatted(
                        listener.getClass().getName(), event), e);
            }
        }
    }

}
