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
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
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

final class WorkflowTaskScheduler implements Closeable {

    private static final long ADVISORY_LOCK_ID = 936942697589618032L;
    private static final String EXECUTOR_NAME = WorkflowTaskScheduler.class.getSimpleName();
    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowTaskScheduler.class);

    private final Jdbi jdbi;
    private final MeterRegistry meterRegistry;
    private final Duration pollInterval;
    private @Nullable ScheduledExecutorService executor;
    private @Nullable MeterProvider<Timer> taskSchedulingLatencyTimer;
    private @Nullable MeterProvider<Counter> tasksScheduledCounter;

    WorkflowTaskScheduler(
            final Jdbi jdbi,
            final MeterRegistry meterRegistry,
            final Duration pollInterval) {
        this.jdbi = jdbi;
        this.meterRegistry = meterRegistry;
        this.pollInterval = pollInterval;
    }

    void start() {
        taskSchedulingLatencyTimer = Timer
                .builder("dt.dex.engine.workflow.task.scheduling.latency")
                .withRegistry(meterRegistry);
        tasksScheduledCounter = Counter
                .builder("dt.dex.engine.workflow.tasks.scheduled")
                .withRegistry(meterRegistry);

        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofVirtual().name(EXECUTOR_NAME).factory());
        new ExecutorServiceMetrics(executor, EXECUTOR_NAME, null)
                .bindTo(meterRegistry);
        executor.scheduleWithFixedDelay(
                () -> {
                    try {
                        scheduleWorkflowTasks();
                    } catch (RuntimeException e) {
                        LOGGER.error("Failed to schedule workflow tasks", e);
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

    private void scheduleWorkflowTasks() {
        jdbi.useTransaction(handle -> {
            if (!tryAcquireAdvisoryLock(handle, ADVISORY_LOCK_ID)) {
                return;
            }

            final List<Queue> queues = getActiveQueuesWithCapacity(handle);
            if (queues.isEmpty()) {
                LOGGER.debug("No active queues with capacity");
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

    private record Queue(String name, int maxConcurrency) {

        private static class RowMapper implements org.jdbi.v3.core.mapper.RowMapper<Queue> {

            @Override
            public Queue map(final ResultSet rs, final StatementContext ctx) throws SQLException {
                return new Queue(rs.getString("name"), rs.getInt("max_concurrency"));
            }

        }

    }

    private List<Queue> getActiveQueuesWithCapacity(final Handle handle) {
        final Query query = handle.createQuery("""
                with cte_candidate as (
                  select name
                       , max_concurrency
                    from dex_workflow_task_queue
                   where status = 'ACTIVE'
                )
                select queue.name
                     , queue.max_concurrency
                  from dex_workflow_task_queue as queue
                 inner join cte_candidate
                    on cte_candidate.name = queue.name
                 where status = 'ACTIVE'
                   and queue.max_concurrency - (
                         select count(*)
                           from dex_workflow_task
                          where queue_name = queue.name
                          limit cte_candidate.max_concurrency
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
                    from dex_workflow_task
                   where queue_name = :queueName
                   limit :maxConcurrency
                ),
                cte_eligible_run as (
                  select id
                       , workflow_name
                       , priority
                    from dex_workflow_run as run
                   where queue_name = :queueName
                     and status = any(cast('{CREATED, RUNNING, SUSPENDED}' as dex_workflow_run_status[]))
                     -- Only consider runs with visible messages in their inbox.
                     and exists(
                       select 1
                         from dex_workflow_run_inbox as inbox
                        where inbox.workflow_run_id = run.id
                          and (visible_from is null or visible_from <= now())
                     )
                     -- Only consider runs for which no task is already queued.
                     and not exists(
                       select 1
                         from dex_workflow_task as task
                        where task.queue_name = :queueName
                          and task.workflow_run_id = run.id
                     )
                   order by priority desc
                          , id
                   limit greatest(0, :maxConcurrency - (select depth from cte_queue_depth))
                )
                insert into dex_workflow_task (queue_name, workflow_run_id, workflow_name, priority)
                select :queueName
                     , id
                     , workflow_name
                     , priority
                  from cte_eligible_run
                on conflict (queue_name, workflow_run_id) do nothing
                returning workflow_name
                """);

        final List<String> scheduledWorkflowNames = update
                .bind("queueName", queue.name())
                .bind("maxConcurrency", queue.maxConcurrency())
                .executeAndReturnGeneratedKeys()
                .mapTo(String.class)
                .list();

        for (final String workflowName : scheduledWorkflowNames) {
            tasksScheduledCounter
                    .withTag("workflowName", workflowName)
                    .increment();
        }
    }

}
