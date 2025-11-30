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
package org.dependencytrack.dex.engine;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Closeable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.dex.engine.support.LockSupport.tryAcquireAdvisoryLock;

final class ActivityTaskScheduler implements Closeable {

    private static final long ADVISORY_LOCK_ID = 2299953353083674283L;
    private static final Logger LOGGER = LoggerFactory.getLogger(ActivityTaskScheduler.class);

    private final Jdbi jdbi;
    private final MeterRegistry meterRegistry;
    private final Duration pollInterval;
    private @Nullable ScheduledExecutorService executor;
    private @Nullable MeterProvider<Timer> taskSchedulingLatencyTimer;
    private @Nullable MeterProvider<Counter> tasksScheduledCounter;

    ActivityTaskScheduler(
            final Jdbi jdbi,
            final MeterRegistry meterRegistry,
            final Duration pollInterval) {
        this.jdbi = jdbi;
        this.meterRegistry = meterRegistry;
        this.pollInterval = pollInterval;
    }

    void start() {
        taskSchedulingLatencyTimer = Timer
                .builder("dt.dex.engine.activity.task.scheduling.latency")
                .withRegistry(meterRegistry);
        tasksScheduledCounter = Counter
                .builder("dt.dex.engine.activity.tasks.scheduled")
                .withRegistry(meterRegistry);

        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name(ActivityTaskScheduler.class.getSimpleName())
                        .factory());
        executor.scheduleWithFixedDelay(
                () -> {
                    try {
                        scheduleActivities();
                    } catch (RuntimeException e) {
                        LOGGER.error("Failed to schedule activity tasks", e);
                    }
                },
                100,
                pollInterval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.close();
        }
    }

    private void scheduleActivities() {
        jdbi.useTransaction(handle -> {
            if (!tryAcquireAdvisoryLock(handle, ADVISORY_LOCK_ID)) {
                LOGGER.debug("Lock is held by another instance");
                return;
            }

            final List<Queue> queues = getActiveQueuesWithCapacity(handle);
            if (queues.isEmpty()) {
                LOGGER.debug("No updated queues");
                return;
            }

            for (final Queue queue : queues) {
                final Timer.Sample latencySample = Timer.start();
                try (var ignored = MDC.putCloseable("queueName", queue.name())) {
                    processQueue(handle, queue);
                } finally {
                    latencySample.stop(
                            taskSchedulingLatencyTimer
                                    .withTag("queueName", queue.name));
                }
            }
        });
    }

    private record Queue(String name, int capacity) {

        private static class RowMapper implements org.jdbi.v3.core.mapper.RowMapper<Queue> {

            @Override
            public Queue map(final ResultSet rs, final StatementContext ctx) throws SQLException {
                return new Queue(rs.getString("name"), rs.getInt("capacity"));
            }

        }

    }

    private List<Queue> getActiveQueuesWithCapacity(final Handle handle) {
        final Query query = handle.createQuery("""
                with cte_candidate as (
                  select name
                       , capacity
                    from dex_activity_task_queue
                   where status = 'ACTIVE'
                )
                select queue.name
                     , queue.capacity
                  from dex_activity_task_queue as queue
                 inner join cte_candidate
                    on cte_candidate.name = queue.name
                 where status = 'ACTIVE'
                   and queue.capacity - (
                         select count(*)
                           from dex_activity_task
                          where queue_name = queue.name
                            and status = 'QUEUED'
                          limit cte_candidate.capacity
                       ) > 0
                """);

        return query
                .map(new Queue.RowMapper())
                .list();
    }

    private void processQueue(final Handle handle, final Queue queue) {
        final Update update = handle.createUpdate("""
                with
                cte_queue_depth as (
                  select count(*) as depth
                    from dex_activity_task
                   where queue_name = :queueName
                     and status = 'QUEUED'
                   limit :capacity
                ),
                cte_eligible_task as (
                  select workflow_run_id
                       , created_event_id
                    from dex_activity_task
                   where queue_name = :queueName
                     -- Only consider tasks that are not already queued.
                     and status != 'QUEUED'
                     -- Only consider tasks that are visible.
                     and (visible_from is null or visible_from <= now())
                   order by priority desc
                          , created_at
                   limit greatest(0, :capacity - (select depth from cte_queue_depth))
                )
                update dex_activity_task as wat
                   set status = 'QUEUED'
                     , updated_at = now()
                  from cte_eligible_task
                 where wat.queue_name = :queueName
                   and wat.workflow_run_id = cte_eligible_task.workflow_run_id
                   and wat.created_event_id = cte_eligible_task.created_event_id
                returning activity_name
                """);

        final List<String> scheduledActivityNames = update
                .bind("queueName", queue.name())
                .bind("capacity", queue.capacity())
                .executeAndReturnGeneratedKeys()
                .mapTo(String.class)
                .list();
        for (final String activityName : scheduledActivityNames) {
            tasksScheduledCounter
                    .withTag("activityName", activityName)
                    .increment();
        }
    }

}
