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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Objects.requireNonNull;

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

        private ScheduledTask(String id, Schedule schedule, Runnable runnable) {
            this.id = requireNonNull(id, "id must not be null");
            this.schedule = requireNonNull(schedule, "schedule must not be null");
            this.runnable = requireNonNull(runnable, "runnable must not be null");
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskScheduler.class);

    private final ScheduledExecutorService executor;
    private final Map<String, ScheduledTask> scheduledTaskById;
    private final AtomicBoolean running = new AtomicBoolean(false);

    TaskScheduler() {
        this.executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name("TaskScheduler-", 0)
                        .factory());
        this.scheduledTaskById = new ConcurrentHashMap<>();
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("Scheduler is already running");
        }
    }

    public TaskScheduler schedule(String id, Schedule schedule, Runnable runnable) {
        if (!running.get()) {
            throw new IllegalStateException("Scheduler must be running to schedule tasks");
        }

        final var task = new ScheduledTask(id, schedule, runnable);

        if (scheduledTaskById.putIfAbsent(id, task) != null) {
            throw new IllegalStateException("A task with ID %s has already been scheduled".formatted(id));
        }

        scheduleNextExecution(task);

        return this;
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            throw new IllegalStateException("Scheduler is already stopped");
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

        LOGGER.debug("Executing task {}", task.id);
        try {
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

        final var now = Instant.now();
        final var nextExecutionAt = task.schedule.next(Date.from(now)).toInstant();
        final long nextExecutionInMillis = Math.max(
                ChronoUnit.MILLIS.between(now, nextExecutionAt), 0);

        task.future = executor.schedule(
                () -> execute(task),
                nextExecutionInMillis,
                TimeUnit.MILLISECONDS);

        LOGGER.debug("Next execution of task {} scheduled for {}", task.id, nextExecutionAt);
    }

}
