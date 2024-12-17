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
package org.dependencytrack.workflow;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.search.MeterNotFoundException;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

public class WorkflowEngineBenchmarkTest extends PersistenceCapableTest {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngineBenchmarkTest.class);

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables()
            .set("ALPINE_METRICS_ENABLED", "true");

    private WorkflowEngine engine;
    private ScheduledExecutorService statsPrinterExecutor;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        statsPrinterExecutor = Executors.newSingleThreadScheduledExecutor();
        statsPrinterExecutor.scheduleAtFixedRate(new StatsReporter(), 3, 5, TimeUnit.SECONDS);

        final var engineConfig = new WorkflowEngineConfig(
                UUID.randomUUID(),
                PersistenceUtil.getDataSource(qm.getPersistenceManager()));
        engineConfig.taskActionBuffer().setFlushInterval(Duration.ofMillis(3));
        engineConfig.taskActionBuffer().setMaxBatchSize(250);
        engineConfig.workflowTaskDispatcher().setMinPollInterval(Duration.ofMillis(5));
        engineConfig.workflowTaskDispatcher().setPollBackoffIntervalFunction(
                IntervalFunction.of(Duration.ofMillis(50)));
        engineConfig.setMeterRegistry(Metrics.getRegistry());

        engine = new WorkflowEngine(engineConfig);
        engine.start();

        engine.registerWorkflowRunner("test", 100, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callActivity("foo", null, voidConverter(), voidConverter(), defaultRetryPolicy()).await();
            ctx.callActivity("bar", null, voidConverter(), voidConverter(), defaultRetryPolicy()).await();
            ctx.callActivity("baz", null, voidConverter(), voidConverter(), defaultRetryPolicy()).await();
            return Optional.empty();
        });

        engine.registerActivityRunner("foo", 50, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> Optional.empty());
        engine.registerActivityRunner("bar", 50, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> Optional.empty());
        engine.registerActivityRunner("baz", 50, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> Optional.empty());
    }

    @After
    @Override
    public void after() {
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

        super.after();
    }

    @Test
    public void test() {
        final int numRuns = 100_000;

        final var scheduleOptions = new ArrayList<ScheduleWorkflowRunOptions>(numRuns);
        for (int i = 0; i < numRuns; i++) {
            final String concurrencyGroupId = (i % 2 == 0 && i != 0) ? "test-" + (i - 1) : "test-" + i;
            final Set<String> tags = (i % 5 == 0) ? Set.of("foo=test-" + i) : null;
            scheduleOptions.add(new ScheduleWorkflowRunOptions("test", 1)
                    .withConcurrencyGroupId(concurrencyGroupId)
                    .withTags(tags));
        }

        engine.scheduleWorkflowRuns(scheduleOptions);
        LOGGER.info("All workflows started");

        await("Workflow completion")
                .atMost(Duration.ofMinutes(10))
                .pollInterval(Duration.ofSeconds(3))
                .untilAsserted(() -> {
                    final boolean isAllRunsCompleted = withJdbiHandle(
                            handle -> handle.createQuery("""
                                            select not exists (
                                                select 1
                                                  from workflow_run
                                                 where status != 'COMPLETED')
                                            """)
                                    .mapTo(Boolean.class)
                                    .one());
                    assertThat(isAllRunsCompleted).isTrue();
                });
    }

    private static class StatsReporter implements Runnable {

        private static final Logger LOGGER = Logger.getLogger(StatsReporter.class);

        @Override
        public void run() {
            LOGGER.info("==========");

            try {
                final List<WorkflowRunCountByNameAndStatusRow> statusRows =
                        withJdbiHandle(handle -> new WorkflowDao(handle).getRunCountByNameAndStatus());
                final Map<WorkflowRunStatus, Long> countByStatus = statusRows.stream()
                        .collect(Collectors.toMap(
                                WorkflowRunCountByNameAndStatusRow::status,
                                WorkflowRunCountByNameAndStatusRow::count));
                LOGGER.info("Statuses: %s".formatted(countByStatus));

                final MeterRegistry meterRegistry = Metrics.getRegistry();
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
                    LOGGER.info("Dispatcher Poll Latency: taskType=%s, mean=%.2fms, max=%.2fms".formatted(
                            timer.getId().getTag("taskType"), timer.mean(TimeUnit.MILLISECONDS), timer.max(TimeUnit.MILLISECONDS)));
                }
                for (final DistributionSummary summary : taskDispatcherPollTasks) {
                    LOGGER.info("Dispatcher Poll Tasks: taskType=%s, mean=%.2f, max=%.2f".formatted(
                            summary.getId().getTag("taskType"), summary.mean(), summary.max()));
                }
                for (final Timer timer : taskProcessLatencies) {
                    LOGGER.info("Task Process Latency: taskType=%s, taskName=%s, mean=%.2f, max=%.2f".formatted(
                            timer.getId().getTag("taskType"), timer.getId().getTag("taskName"), timer.mean(TimeUnit.MILLISECONDS), timer.max(TimeUnit.MILLISECONDS)));
                }

                for (final Timer timer : bufferFlushLatencies) {
                    LOGGER.info("Buffer Flush Latency: buffer=%s, mean=%.2fms, max=%.2fms".formatted(
                            timer.getId().getTag("buffer"), timer.mean(TimeUnit.MILLISECONDS), timer.max(TimeUnit.MILLISECONDS)));
                }
                for (final DistributionSummary summary : bufferBatchSizes) {
                    LOGGER.info("Buffer Batch Size: buffer=%s, mean=%.2f, max=%.2f".formatted(
                            summary.getId().getTag("buffer"), summary.mean(), summary.max()));
                }
            } catch (MeterNotFoundException e) {
                LOGGER.warn("Meters not ready yet");
            }
        }
    }

}