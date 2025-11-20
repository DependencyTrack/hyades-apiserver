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

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.search.MeterNotFoundException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivityExecutor;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowExecutor;
import org.dependencytrack.dex.api.annotation.Activity;
import org.dependencytrack.dex.api.annotation.Workflow;
import org.dependencytrack.dex.engine.api.ActivityTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.WorkflowTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.request.CreateActivityTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowTaskQueueRequest;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

@Disabled
@Testcontainers
public class DexEngineImplBenchmarkTest {

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer();

    @Activity(name = "foo")
    public static class TestActivityFoo implements ActivityExecutor<Void, Void> {

        @Override
        public Void execute(final @NonNull ActivityContext ctx, final Void argument) {
            return null;
        }

    }

    @Activity(name = "bar")
    public static class TestActivityBar implements ActivityExecutor<Void, Void> {

        @Override
        public Void execute(final @NonNull ActivityContext ctx, final Void argument) {
            return null;
        }

    }

    @Activity(name = "baz")
    public static class TestActivityBaz implements ActivityExecutor<Void, Void> {

        @Override
        public Void execute(final @NonNull ActivityContext ctx, final Void argument) {
            return null;
        }

    }

    @Workflow(name = "test")
    public static class TestWorkflow implements WorkflowExecutor<Void, Void> {

        @Override
        public Void execute(final @NonNull WorkflowContext<Void> ctx, final Void argument) {
            ctx.activity(TestActivityFoo.class).call(new ActivityCallOptions<>()).await();
            ctx.activity(TestActivityBar.class).call(new ActivityCallOptions<>()).await();
            ctx.activity(TestActivityBaz.class).call(new ActivityCallOptions<>()).await();
            return null;
        }

    }

    private DexEngineImpl engine;
    private ScheduledExecutorService statsPrinterExecutor;

    @BeforeEach
    void beforeEach() {
        final var hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(postgresContainer.getJdbcUrl());
        hikariConfig.setUsername(postgresContainer.getUsername());
        hikariConfig.setPassword(postgresContainer.getPassword());
        hikariConfig.setMaximumPoolSize(5);
        hikariConfig.setMinimumIdle(5);
        final var dataSource = new HikariDataSource(hikariConfig);

        final var meterRegistry = new SimpleMeterRegistry();

        statsPrinterExecutor = Executors.newSingleThreadScheduledExecutor();
        statsPrinterExecutor.scheduleAtFixedRate(new StatsReporter(meterRegistry), 3, 5, TimeUnit.SECONDS);

        final var engineConfig = new DexEngineConfig(UUID.randomUUID(), dataSource);
        engineConfig.retention().setWorkerEnabled(false);
        engineConfig.runHistoryCache().setEvictAfterAccess(Duration.ofMinutes(1));
        engineConfig.runHistoryCache().setMaxSize(10_000);
        engineConfig.taskCommandBuffer().setFlushInterval(Duration.ofMillis(3));
        engineConfig.taskCommandBuffer().setMaxBatchSize(250);
        engineConfig.workflowTaskWorker().setMinPollInterval(Duration.ofMillis(5));
        engineConfig.workflowTaskWorker().setPollBackoffIntervalFunction(IntervalFunction.of(Duration.ofMillis(50)));
        engineConfig.activityTaskWorker().setMinPollInterval(Duration.ofMillis(5));
        engineConfig.activityTaskWorker().setPollBackoffIntervalFunction(IntervalFunction.of(Duration.ofMillis(50)));
        engineConfig.activityTaskScheduler().setPollInterval(Duration.ofMillis(100));
        engineConfig.setMeterRegistry(meterRegistry);

        engine = new DexEngineImpl(engineConfig);
        engine.registerWorkflow(new TestWorkflow(), voidConverter(), voidConverter(), Duration.ofSeconds(5));
        engine.registerActivity(new TestActivityFoo(), voidConverter(), voidConverter(), Duration.ofSeconds(5), false);
        engine.registerActivity(new TestActivityBar(), voidConverter(), voidConverter(), Duration.ofSeconds(5), false);
        engine.registerActivity(new TestActivityBaz(), voidConverter(), voidConverter(), Duration.ofSeconds(5), false);

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", "default", 100));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", "default", 150));

        engine.createWorkflowTaskQueue(new CreateWorkflowTaskQueueRequest("default", 1000));
        engine.createActivityTaskQueue(new CreateActivityTaskQueueRequest("default", 1000));
    }

    @AfterEach
    void afterEach() {
        if (engine != null) {
            try {
                engine.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        if (statsPrinterExecutor != null) {
            statsPrinterExecutor.close();
        }
    }

    @Test
    void test() throws Exception {
        final int numRuns = 100_000;

        // Whether to use concurrency groups for *all* workflow runs.
        // Disabling this will significantly improve throughput.
        // Note that realistic workloads will have a balance between
        // runs that use concurrency groups, and runs that don't.
        final boolean withConcurrencyGroups = true;

        final var scheduleOptions = new ArrayList<CreateWorkflowRunRequest<?>>(numRuns);
        for (int i = 0; i < numRuns; i++) {
            final String concurrencyGroupId = withConcurrencyGroups
                    ? ((i % 2 == 0 && i != 0) ? "test-" + (i - 1) : "test-" + i)
                    : null;

            final Map<String, String> labels = (i % 5 == 0) ? Map.of("foo", "test-" + i) : null;

            scheduleOptions.add(
                    new CreateWorkflowRunRequest<>("test", 1, "default")
                            .withConcurrencyGroupId(concurrencyGroupId)
                            .withLabels(labels));
        }

        System.out.printf("Creating %d runs\n", numRuns);
        engine.createRuns(scheduleOptions);

        // Ensure table statistics are up to date.
        // Under normal circumstances, there would never be bulk inserts of that many runs at once.
        System.out.println("Running ANALYZE");
        try (final Connection connection = postgresContainer.createConnection("")) {
            connection.createStatement().execute("ANALYZE");
        }

        System.out.println("Starting engine");
        engine.start();

        await("Workflow completion")
                .atMost(Duration.ofMinutes(10))
                .pollInterval(Duration.ofSeconds(3))
                .untilAsserted(() -> {
                    final long notCompletedRuns = engine.getRunStats().stream()
                            .filter(row -> row.status() != WorkflowRunStatus.COMPLETED)
                            .map(WorkflowRunCountByNameAndStatusRow::count)
                            .mapToInt(Math::toIntExact)
                            .sum();
                    assertThat(notCompletedRuns).isZero();
                });
    }

    private class StatsReporter implements Runnable {

        private final MeterRegistry meterRegistry;

        private StatsReporter(final MeterRegistry meterRegistry) {
            this.meterRegistry = meterRegistry;
        }

        @Override
        public void run() {
            if (engine == null || engine.status() != DexEngineImpl.Status.RUNNING) {
                System.out.println("Engine not ready yet");
                return;
            }

            System.out.println("==========");

            try {
                final List<WorkflowRunCountByNameAndStatusRow> statusRows = engine.getRunStats();
                final Map<WorkflowRunStatus, Long> countByStatus = statusRows.stream()
                        .collect(Collectors.toMap(
                                WorkflowRunCountByNameAndStatusRow::status,
                                WorkflowRunCountByNameAndStatusRow::count));
                System.out.printf("Statuses: %s\n".formatted(countByStatus));

                final Collection<Timer> workflowTaskSchedulingLatencies = meterRegistry.get(
                        "dt.dex.engine.workflow.task.scheduling.latency").timers();
                final Collection<Timer> activityTaskSchedulingLatencies = meterRegistry.get(
                        "dt.dex.engine.activity.task.scheduling.latency").timers();
                final Collection<Timer> taskWorkerPollLatencies = meterRegistry.get(
                        "dt.dex.engine.task.worker.poll.latency").timers();
                final Collection<DistributionSummary> taskWorkerPollTasks = meterRegistry.get(
                        "dt.dex.engine.task.worker.tasks.polled").summaries();
                final Collection<Timer> taskProcessLatencies = meterRegistry.get(
                        "dt.dex.engine.task.worker.process.latency").timers();
                final Collection<Timer> bufferFlushLatencies = meterRegistry.get(
                        "dt.dex.engine.buffer.flush.latency").timers();
                final Collection<DistributionSummary> bufferBatchSizes = meterRegistry.get(
                        "dt.dex.engine.buffer.flush.batch.size").summaries();
                final Collection<FunctionCounter> historyCacheGets = meterRegistry.get(
                        "cache.gets").tag("cache", "DexEngine-RunHistoryCache").functionCounters();

                for (final Timer timer : workflowTaskSchedulingLatencies) {
                    System.out.printf(
                            "Workflow Task Scheduling Latency: queueName=%s, mean=%.2fms, max=%.2fms\n",
                            timer.getId().getTag("queueName"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }
                for (final Timer timer : activityTaskSchedulingLatencies) {
                    System.out.printf(
                            "Activity Task Scheduling Latency: queueName=%s, mean=%.2fms, max=%.2fms\n",
                            timer.getId().getTag("queueName"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }
                for (final Timer timer : taskWorkerPollLatencies) {
                    System.out.printf(
                            "Worker Poll Latency: workerType=%s, mean=%.2fms, max=%.2fms\n",
                            timer.getId().getTag("workerType"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }
                for (final DistributionSummary summary : taskWorkerPollTasks) {
                    System.out.printf(
                            "Worker Poll Tasks: workerType=%s, mean=%.2f, max=%.2f\n",
                            summary.getId().getTag("workerType"),
                            summary.mean(),
                            summary.max());
                }
                for (final Timer timer : taskProcessLatencies) {
                    System.out.printf(
                            "Worker Task Process Latency: workerType=%s, mean=%.2fms, max=%.2fms\n",
                            timer.getId().getTag("workerType"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }

                for (final Timer timer : bufferFlushLatencies) {
                    System.out.printf(
                            "Buffer Flush Latency: buffer=%s, mean=%.2fms, max=%.2fms\n",
                            timer.getId().getTag("buffer"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }
                for (final DistributionSummary summary : bufferBatchSizes) {
                    System.out.printf(
                            "Buffer Batch Size: buffer=%s, mean=%.2f, max=%.2f\n",
                            summary.getId().getTag("buffer"),
                            summary.mean(),
                            summary.max());
                }

                for (final FunctionCounter counter : historyCacheGets) {
                    System.out.printf(
                            "History Cache Gets: result=%s, count=%.2f\n",
                            counter.getId().getTag("result"),
                            counter.count());
                }
            } catch (MeterNotFoundException e) {
                System.out.println("Meters not ready yet");
            }

            try (final Connection connection = postgresContainer.createConnection("")) {
                final PreparedStatement ps = connection.prepareStatement("""
                        select relname as table_name
                             , n_tup_upd as updates
                             , n_tup_hot_upd as hot_updates
                             , (n_tup_hot_upd::real / nullif(n_tup_upd, 0)::real)::real as hot_update_ratio
                          from pg_stat_user_tables
                         where relname like 'dex_%'
                           and n_tup_upd > 0
                         order by hot_update_ratio desc
                        """);
                final ResultSet rs = ps.executeQuery();
                while (rs.next()) {
                    System.out.printf(
                            "HOT Updates: table=%s, updates=%d, hot_updates=%d, ratio=%.2f\n",
                            rs.getString(1), rs.getLong(2), rs.getLong(3), rs.getDouble(4));
                }
            } catch (SQLException e) {
                System.out.println("Database not ready yet: " + e.getMessage());
            }
        }
    }

}