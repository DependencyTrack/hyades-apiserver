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
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.search.MeterNotFoundException;
import org.dependencytrack.PersistenceCapableTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

public class WorkflowEngineBenchmarkTest extends PersistenceCapableTest {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngineBenchmarkTest.class);

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    private WorkflowEngine engine;
    private ScheduledExecutorService statsPrinterExecutor;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        environmentVariables.set("ALPINE_METRICS_ENABLED", "true");

        statsPrinterExecutor = Executors.newSingleThreadScheduledExecutor();
        statsPrinterExecutor.scheduleAtFixedRate(new StatsReporter(), 1, 5, TimeUnit.SECONDS);

        engine = new WorkflowEngine();
        engine.start();

        engine.registerWorkflowRunner("test", 10, voidConverter(), voidConverter(), ctx -> {
            ctx.callActivity("foo", null, voidConverter(), voidConverter()).await();
            ctx.callActivity("bar", null, voidConverter(), voidConverter()).await();
            ctx.callActivity("baz", null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerActivityRunner("foo", 5, voidConverter(), voidConverter(), ctx -> Optional.empty());
        engine.registerActivityRunner("bar", 5, voidConverter(), voidConverter(), ctx -> Optional.empty());
        engine.registerActivityRunner("baz", 5, voidConverter(), voidConverter(), ctx -> Optional.empty());
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
            statsPrinterExecutor.shutdown();
            try {
                statsPrinterExecutor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        super.after();
    }

    @Test
    public void test() {
        final var scheduleOptions = new ArrayList<ScheduleWorkflowRunOptions>(10_000);
        for (int i = 0; i < 10_000; i++) {
            scheduleOptions.add(new ScheduleWorkflowRunOptions("test", 1));
        }

        engine.scheduleWorkflowRuns(scheduleOptions);
        LOGGER.info("All workflows started");

        await("Workflow completion")
                .atMost(Duration.ofMinutes(5))
                .pollInterval(Duration.ofSeconds(3))
                .untilAsserted(() -> {
                    final long completedWorkflows = withJdbiHandle(
                            handle -> handle.createQuery("""
                                            SELECT COUNT(*) FROM "WORKFLOW_RUN" WHERE "STATUS" = 'WORKFLOW_RUN_STATUS_COMPLETED'
                                            """)
                                    .mapTo(Long.class)
                                    .one());
                    LOGGER.info("Completed workflows: " + completedWorkflows);
                    assertThat(completedWorkflows).isEqualTo(10_000);
                });
    }

    private static class StatsReporter implements Runnable {

        private static final Logger LOGGER = Logger.getLogger(StatsReporter.class);

        @Override
        public void run() {
            try {
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
                    LOGGER.info("Task Process Latency: taskType=%s, mean=%.2f, max=%.2f".formatted(
                            timer.getId().getTag("taskType"), timer.mean(TimeUnit.MILLISECONDS), timer.max(TimeUnit.MILLISECONDS)));
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