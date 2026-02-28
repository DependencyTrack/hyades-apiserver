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
package org.dependencytrack.tasks;

import com.asahaf.javacron.Schedule;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @author Steve Springett
 * @since 3.0.0
 */
public final class TaskScheduler implements Closeable {

    private static class ScheduledTask {

        private final String id;
        private final Schedule schedule;
        private final Runnable runnable;
        private ScheduledFuture<?> future;
        private long expectedLockVersion;

        private ScheduledTask(String id, Schedule schedule, Runnable runnable) {
            this.id = requireNonNull(id, "id must not be null");
            this.schedule = requireNonNull(schedule, "schedule must not be null");
            this.runnable = requireNonNull(runnable, "runnable must not be null");
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskScheduler.class);
    private static final Duration DEFAULT_IMMEDIATE_EXECUTION_MIN_DELAY = Duration.ofSeconds(15);
    private static final Duration DEFAULT_IMMEDIATE_EXECUTION_MAX_DELAY = Duration.ofMinutes(2);

    private final ScheduledExecutorService executor;
    private final Map<String, ScheduledTask> scheduledTaskById;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Duration immediateExecutionMinDelay;
    private final Duration immediateExecutionMaxDelay;

    TaskScheduler() {
        this(DEFAULT_IMMEDIATE_EXECUTION_MIN_DELAY, DEFAULT_IMMEDIATE_EXECUTION_MAX_DELAY);
    }

    TaskScheduler(
            Duration immediateExecutionMinDelay,
            Duration immediateExecutionMaxDelay) {
        requireNonNull(immediateExecutionMinDelay, "immediateExecutionMinDelay must not be null");
        requireNonNull(immediateExecutionMaxDelay, "immediateExecutionMaxDelay must not be null");
        if (immediateExecutionMinDelay.isNegative()
                || immediateExecutionMaxDelay.compareTo(immediateExecutionMinDelay) <= 0) {
            throw new IllegalArgumentException(
                    "immediateExecutionMaxDelay must be greater than immediateExecutionMinDelay");
        }
        this.executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name("TaskScheduler-", 0)
                        .factory());
        this.scheduledTaskById = new ConcurrentHashMap<>();
        this.immediateExecutionMinDelay = immediateExecutionMinDelay;
        this.immediateExecutionMaxDelay = immediateExecutionMaxDelay;
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("Scheduler is already running");
        }
    }

    public TaskScheduler schedule(String id, Schedule schedule, Runnable runnable) {
        return schedule(id, schedule, runnable, false);
    }

    public TaskScheduler schedule(String id, Schedule schedule, Runnable runnable, boolean triggerOnFirstRun) {
        if (!running.get()) {
            throw new IllegalStateException("Scheduler must be running to schedule tasks");
        }

        final var task = new ScheduledTask(id, schedule, runnable);

        if (scheduledTaskById.putIfAbsent(id, task) != null) {
            throw new IllegalStateException("A task with ID %s has already been scheduled".formatted(id));
        }

        try {
            final Instant lastExecutedAt = getLastExecutedAt(id);
            if (lastExecutedAt != null) {
                final var nextExpected = task.schedule.next(Date.from(lastExecutedAt)).toInstant();
                if (!nextExpected.isAfter(Instant.now())) {
                    task.expectedLockVersion = claimExecution(id);
                    final long delayMillis = ThreadLocalRandom.current().nextLong(
                            immediateExecutionMinDelay.toMillis(),
                            immediateExecutionMaxDelay.toMillis());
                    LOGGER.info("Detected missed execution for task {}; executing in {}ms", id, delayMillis);
                    task.future = executor.schedule(() -> execute(task), delayMillis, TimeUnit.MILLISECONDS);
                    return this;
                }
            } else if (triggerOnFirstRun) {
                task.expectedLockVersion = claimExecution(id);
                final long delayMillis = ThreadLocalRandom.current().nextLong(
                        immediateExecutionMinDelay.toMillis(),
                        immediateExecutionMaxDelay.toMillis());
                LOGGER.info("First run of task {}; executing in {}ms", id, delayMillis);
                task.future = executor.schedule(() -> execute(task), delayMillis, TimeUnit.MILLISECONDS);
                return this;
            }

            scheduleNextExecution(task);
        } catch (RuntimeException e) {
            scheduledTaskById.remove(id, task);
            throw e;
        }

        return this;
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            return;
        }

        for (final ScheduledTask task : scheduledTaskById.values()) {
            if (task.future != null && !task.future.isDone()) {
                LOGGER.debug("Cancelling future for task {}", task.id);
                task.future.cancel(false);
            }
        }

        scheduledTaskById.clear();
        executor.close();
    }

    boolean isRunning() {
        return running.get();
    }

    Set<String> scheduledTaskIds() {
        return Set.copyOf(scheduledTaskById.keySet());
    }

    private void execute(ScheduledTask task) {
        if (!running.get()) {
            LOGGER.debug("Not executing task {} because scheduler is stopped", task.id);
            return;
        }

        try {
            if (!tryRecordExecution(task.id, Instant.now(), task.expectedLockVersion)) {
                LOGGER.debug("Task {} was already executed by another node; skipping", task.id);
                return;
            }

            LOGGER.debug("Executing task {}", task.id);
            task.runnable.run();
        } catch (Throwable t) {
            LOGGER.error("Failed to execute task {}", task.id, t);
        } finally {
            scheduleNextExecution(task);
        }
    }

    private void scheduleNextExecution(ScheduledTask task) {
        if (!running.get()) {
            LOGGER.debug("Not scheduling next execution for task {} because scheduler is stopped", task.id);
            return;
        }

        if (task.future != null && !task.future.isDone()) {
            LOGGER.debug("Cancelling pending future for task {}", task.id);
            task.future.cancel(false);
        }

        try {
            task.expectedLockVersion = claimExecution(task.id);
        } catch (Exception e) {
            LOGGER.error("Failed to claim next execution for task {}; retrying in 30s", task.id, e);
            task.future = executor.schedule(
                    () -> scheduleNextExecution(task), 30, TimeUnit.SECONDS);
            return;
        }

        // Truncate "now" to seconds, and ensure it's at least 1s after the
        // previous task execution finished. Otherwise, we could end up scheduling
        // the next execution immediately. The cron library used to calculate
        // schedules operates at second precision.
        final var now = Instant.now().truncatedTo(ChronoUnit.SECONDS).plusSeconds(1);

        final var nextExecutionAt = task.schedule.next(Date.from(now)).toInstant();
        final long nextExecutionInMillis = Math.max(
                ChronoUnit.MILLIS.between(Instant.now(), nextExecutionAt), 0);

        task.future = executor.schedule(
                () -> execute(task),
                nextExecutionInMillis,
                TimeUnit.MILLISECONDS);

        LOGGER.debug("Next execution of task {} scheduled for {}", task.id, nextExecutionAt);
    }

    private static @Nullable Instant getLastExecutedAt(String taskId) {
        return withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "LAST_EXECUTED_AT"
                          FROM "SCHEDULED_TASK_EXECUTION"
                         WHERE "TASK_ID" = :taskId
                        """)
                .bind("taskId", taskId)
                .mapTo(Instant.class)
                .findOne()
                .orElse(null));
    }

    private static long claimExecution(String taskId) {
        return inJdbiTransaction(handle -> handle
                .createQuery("""
                        INSERT INTO "SCHEDULED_TASK_EXECUTION" ("TASK_ID", "LOCK_VERSION")
                        VALUES (:taskId, 1)
                        ON CONFLICT ("TASK_ID") DO UPDATE
                        SET "LOCK_VERSION" = "SCHEDULED_TASK_EXECUTION"."LOCK_VERSION" + 1
                        RETURNING "LOCK_VERSION"
                        """)
                .bind("taskId", taskId)
                .mapTo(Long.class)
                .one());
    }

    private static boolean tryRecordExecution(String taskId, Instant executedAt, long expectedLockVersion) {
        final int updatedRows = inJdbiTransaction(handle -> handle
                .createUpdate("""
                        UPDATE "SCHEDULED_TASK_EXECUTION"
                           SET "LAST_EXECUTED_AT" = :executedAt
                         WHERE "TASK_ID" = :taskId
                           AND "LOCK_VERSION" = :expectedLockVersion
                        """)
                .bind("taskId", taskId)
                .bind("executedAt", executedAt)
                .bind("expectedLockVersion", expectedLockVersion)
                .execute());
        return updatedRows > 0;
    }

}
