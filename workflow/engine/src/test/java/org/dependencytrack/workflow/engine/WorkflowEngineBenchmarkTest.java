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
package org.dependencytrack.workflow.engine;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.search.MeterNotFoundException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.workflow.api.ActivityCallOptions;
import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.ActivityGroup;
import org.dependencytrack.workflow.api.WorkflowContext;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.WorkflowGroup;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.voidConverter;

@Disabled
@Testcontainers
public class WorkflowEngineBenchmarkTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineBenchmarkTest.class);

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer()
            .withCommand(
                    "postgres",
                    "-c", "fsync=off", // Testcontainers default.
                    // Allow Autovacuum to run more often and with fewer constraints.
                    // Necessary here because tasks are essentially no-op and thus accumulate
                    // lots of bloat in a very short period of time. This is usually not true
                    // in production workloads, where activities involve I/O and take upwards
                    // of a few seconds. https://tembo.io/blog/optimizing-postgres-auto-vacuum
                    "-c", "autovacuum_vacuum_cost_delay=0",
                    "-c", "autovacuum_naptime=10s",
                    // Avoid too frequent checkpointing.
                    "-c", "min_wal_size=1GB",
                    "-c", "max_wal_size=4GB",
                    "-c", "wal_compression=on");

    @Activity(name = "foo")
    public static class TestActivityFoo implements ActivityExecutor<Void, Void> {

        @Override
        public Optional<Void> execute(final ActivityContext<Void> ctx) {
            return Optional.empty();
        }

    }

    @Activity(name = "bar")
    public static class TestActivityBar implements ActivityExecutor<Void, Void> {

        @Override
        public Optional<Void> execute(final ActivityContext<Void> ctx) {
            return Optional.empty();
        }

    }

    @Activity(name = "baz")
    public static class TestActivityBaz implements ActivityExecutor<Void, Void> {

        @Override
        public Optional<Void> execute(final ActivityContext<Void> ctx) {
            return Optional.empty();
        }

    }

    @Workflow(name = "test")
    public static class TestWorkflow implements WorkflowExecutor<Void, Void> {

        @Override
        public Optional<Void> execute(final WorkflowContext<Void> ctx) {
            ctx.activityClient(TestActivityFoo.class).call(new ActivityCallOptions<>()).await();
            ctx.activityClient(TestActivityBar.class).call(new ActivityCallOptions<>()).await();
            ctx.activityClient(TestActivityBaz.class).call(new ActivityCallOptions<>()).await();
            return Optional.empty();
        }

    }

    private WorkflowEngine engine;
    private ScheduledExecutorService statsPrinterExecutor;

    @BeforeEach
    void beforeEach() {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        final var meterRegistry = new SimpleMeterRegistry();

        statsPrinterExecutor = Executors.newSingleThreadScheduledExecutor();
        statsPrinterExecutor.scheduleAtFixedRate(new StatsReporter(meterRegistry), 3, 5, TimeUnit.SECONDS);

        final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);
        engineConfig.retention().setWorkerEnabled(false);
        engineConfig.scheduler().setEnabled(false);
        engineConfig.runJournalCache().setEvictAfterAccess(Duration.ofMinutes(1));
        engineConfig.runJournalCache().setMaxSize(10_000);
        engineConfig.taskCommandBuffer().setFlushInterval(Duration.ofMillis(3));
        engineConfig.taskCommandBuffer().setMaxBatchSize(250);
        engineConfig.workflowTaskDispatcher().setMinPollInterval(Duration.ofMillis(5));
        engineConfig.workflowTaskDispatcher().setPollBackoffIntervalFunction(IntervalFunction.of(Duration.ofMillis(50)));
        engineConfig.activityTaskDispatcher().setMinPollInterval(Duration.ofMillis(5));
        engineConfig.activityTaskDispatcher().setPollBackoffIntervalFunction(IntervalFunction.of(Duration.ofMillis(50)));
        engineConfig.setMeterRegistry(meterRegistry);

        engine = new WorkflowEngine(engineConfig);
        engine.register(new TestWorkflow(), voidConverter(), voidConverter(), Duration.ofSeconds(5));
        engine.register(new TestActivityFoo(), voidConverter(), voidConverter(), Duration.ofSeconds(5));
        engine.register(new TestActivityBar(), voidConverter(), voidConverter(), Duration.ofSeconds(5));
        engine.register(new TestActivityBaz(), voidConverter(), voidConverter(), Duration.ofSeconds(5));
        engine.start();

        engine.mount(new WorkflowGroup("test")
                .withWorkflow(TestWorkflow.class)
                .withMaxConcurrency(100));
        engine.mount(new ActivityGroup("test")
                .withActivity(TestActivityFoo.class)
                .withActivity(TestActivityBar.class)
                .withActivity(TestActivityBaz.class)
                .withMaxConcurrency(150));
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
    void test() {
        final int numRuns = 100_000;

        final var scheduleOptions = new ArrayList<ScheduleWorkflowRunOptions>(numRuns);
        for (int i = 0; i < numRuns; i++) {
            final String concurrencyGroupId = (i % 2 == 0 && i != 0) ? "test-" + (i - 1) : "test-" + i;
            final Map<String, String> labels = (i % 5 == 0) ? Map.of("foo", "test-" + i) : null;
            scheduleOptions.add(new ScheduleWorkflowRunOptions("test", 1)
                    .withConcurrencyGroupId(concurrencyGroupId)
                    .withLabels(labels));
        }

        engine.scheduleWorkflowRuns(scheduleOptions);
        LOGGER.info("All workflows started");

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

        private static final Logger LOGGER = LoggerFactory.getLogger(StatsReporter.class);

        private final MeterRegistry meterRegistry;

        private StatsReporter(final MeterRegistry meterRegistry) {
            this.meterRegistry = meterRegistry;
        }

        @Override
        public void run() {
            if (engine == null || engine.status() != WorkflowEngine.Status.RUNNING) {
                LOGGER.info("Engine not ready yet");
                return;
            }

            LOGGER.info("==========");

            try {
                final List<WorkflowRunCountByNameAndStatusRow> statusRows = engine.getRunStats();
                final Map<WorkflowRunStatus, Long> countByStatus = statusRows.stream()
                        .collect(Collectors.toMap(
                                WorkflowRunCountByNameAndStatusRow::status,
                                WorkflowRunCountByNameAndStatusRow::count));
                LOGGER.info("Statuses: {}", countByStatus);

                final Collection<Timer> taskDispatcherPollLatencies = meterRegistry.get(
                        "dtrack.workflow.task.dispatcher.poll.latency").timers();
                final Collection<DistributionSummary> taskDispatcherPollTasks = meterRegistry.get(
                        "dtrack.workflow.task.dispatcher.poll.tasks").summaries();
                final Collection<Timer> taskProcessLatencies = meterRegistry.get(
                        "dtrack.workflow.task.process.latency").timers();
                final Collection<Timer> bufferFlushLatencies = meterRegistry.get(
                        "dtrack.buffer.flush.latency").timers();
                final Collection<DistributionSummary> bufferBatchSizes = meterRegistry.get(
                        "dtrack.buffer.flush.batch.size").summaries();

                for (final Timer timer : taskDispatcherPollLatencies) {
                    LOGGER.info(
                            "Dispatcher Poll Latency: taskType={}, taskManager={}, mean={}ms, max={}ms",
                            timer.getId().getTag("taskType"),
                            timer.getId().getTag("taskManager"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }
                for (final DistributionSummary summary : taskDispatcherPollTasks) {
                    LOGGER.info(
                            "Dispatcher Poll Tasks: taskType={}, taskManager={}, taskName={}, mean={}, max={}",
                            summary.getId().getTag("taskType"),
                            summary.getId().getTag("taskManager"),
                            summary.getId().getTag("taskName"),
                            summary.mean(),
                            summary.max());
                }
                for (final Timer timer : taskProcessLatencies) {
                    LOGGER.info(
                            "Task Process Latency: taskType={}, taskManager={}, taskName={}, mean={}ms, max={}ms",
                            timer.getId().getTag("taskType"),
                            timer.getId().getTag("taskManager"),
                            timer.getId().getTag("taskName"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }

                for (final Timer timer : bufferFlushLatencies) {
                    LOGGER.info(
                            "Buffer Flush Latency: buffer={}, mean={}ms, max={}ms",
                            timer.getId().getTag("buffer"),
                            timer.mean(TimeUnit.MILLISECONDS),
                            timer.max(TimeUnit.MILLISECONDS));
                }
                for (final DistributionSummary summary : bufferBatchSizes) {
                    LOGGER.info(
                            "Buffer Batch Size: buffer={}, mean={}, max={}",
                            summary.getId().getTag("buffer"),
                            summary.mean(),
                            summary.max());
                }
            } catch (MeterNotFoundException e) {
                LOGGER.warn("Meters not ready yet");
            }

            try (final Connection connection = postgresContainer.createConnection("")) {
                final PreparedStatement ps = connection.prepareStatement("""
                        select relname as table_name
                             , n_tup_upd as updates
                             , n_tup_hot_upd as hot_updates
                             , (n_tup_hot_upd::real / nullif(n_tup_upd, 0)::real)::real as hot_update_ratio
                          from pg_stat_user_tables
                         where relname like 'workflow_%'
                           and n_tup_upd > 0
                         order by hot_update_ratio desc
                        """);
                final ResultSet rs = ps.executeQuery();
                while (rs.next()) {
                    LOGGER.info(
                            "HOT Updates: table={}, updates={}, hot_updates={}, ratio={}",
                            rs.getString(1), rs.getLong(2), rs.getLong(3), rs.getDouble(4));
                }
            } catch (SQLException e) {
                LOGGER.warn("Database not ready yet", e);
            }
        }
    }

}