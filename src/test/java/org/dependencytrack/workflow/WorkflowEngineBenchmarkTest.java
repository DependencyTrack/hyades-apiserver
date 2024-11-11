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
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.search.MeterNotFoundException;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.workflow.model.StartWorkflowOptions;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.kafka.KafkaContainer;

import java.io.IOException;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

public class WorkflowEngineBenchmarkTest extends PersistenceCapableTest {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngineBenchmarkTest.class);

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Rule
    public KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.8.0");

    private WorkflowEngine engine;
    private ScheduledExecutorService statsPrinterExecutor;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        environmentVariables.set("KAFKA_BOOTSTRAP_SERVERS", kafkaContainer.getBootstrapServers());
        environmentVariables.set("ALPINE_METRICS_ENABLED", "true");

        try (final var adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.createTopics(List.of(new NewTopic("dtrack.event.workflow", 3, (short) 1))).all().get();
        }

        statsPrinterExecutor = Executors.newSingleThreadScheduledExecutor();
        statsPrinterExecutor.scheduleAtFixedRate(new StatsReporter(), 1, 5, TimeUnit.SECONDS);

        engine = new WorkflowEngine();
        engine.start();

        engine.registerWorkflowRunner("test", 10, voidConverter(), voidConverter(), ctx -> {
            ctx.callActivity("foo", "1", null, voidConverter(), voidConverter(), Duration.ZERO);
            ctx.callActivity("bar", "2", null, voidConverter(), voidConverter(), Duration.ZERO);
            ctx.callActivity("baz", "3", null, voidConverter(), voidConverter(), Duration.ZERO);
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
        for (int i = 0; i < 10_000; i++) {
            engine.startWorkflow(new StartWorkflowOptions("test", 1));
        }
        LOGGER.info("All workflows started");

        await("Workflow completion")
                .atMost(Duration.ofMinutes(5))
                .pollInterval(Duration.ofSeconds(3))
                .untilAsserted(() -> {
                    final long completedWorkflows = withJdbiHandle(
                            handle -> handle.createQuery("""
                                            SELECT COUNT(*) FROM "WORKFLOW_RUN" WHERE "STATUS" = 'COMPLETED'
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
                final Collection<Timer> runnerProcessLatencies = meterRegistry.get(
                        "dtrack.workflow.task.runner.process.latency").timers();
                final Timer eventFlushLatency = meterRegistry.get(
                        "dtrack.kafka.batch.consumer.flush.latency").timer();
                final DistributionSummary eventBatchSize = meterRegistry.get(
                        "dtrack.kafka.batch.consumer.flush.batch.size").summary();
                final Gauge kafkaProducerBatchSizeAvg = meterRegistry.get(
                        "kafka.producer.batch.size.avg").gauge();
                final Gauge kafkaProducerBatchSizeMax = meterRegistry.get(
                        "kafka.producer.batch.size.max").gauge();
                final Gauge kafkaProducerQueueTimeAvg = meterRegistry.get(
                        "kafka.producer.record.queue.time.avg").gauge();
                final Gauge kafkaProducerQueueTimeMax = meterRegistry.get(
                        "kafka.producer.record.queue.time.max").gauge();

                for (final Timer timer : taskDispatcherPollLatencies) {
                    LOGGER.info("Dispatcher Poll Latency: queue=%s, mean=%.2fms, max=%.2fms".formatted(
                            timer.getId().getTag("taskQueue"), timer.mean(TimeUnit.MILLISECONDS), timer.max(TimeUnit.MILLISECONDS)));
                }
                for (final DistributionSummary summary : taskDispatcherPollTasks) {
                    LOGGER.info("Dispatcher Poll Tasks: queue=%s, mean=%.2f, max=%.2f".formatted(
                            summary.getId().getTag("taskQueue"), summary.mean(), summary.max()));
                }

                for (final Timer timer : runnerProcessLatencies) {
                    LOGGER.info("Runner Process Latency: queue=%s, mean=%.2fms, max=%.2fms".formatted(
                            timer.getId().getTag("taskQueue"), timer.mean(TimeUnit.MILLISECONDS), timer.max(TimeUnit.MILLISECONDS)));
                }

                LOGGER.info("Event Batch Size: mean=%.2f, max=%.2f".formatted(
                        eventBatchSize.mean(), eventBatchSize.max()));

                LOGGER.info("Event Flush Latency: mean=%.2fms, max=%.2fms".formatted(
                        eventFlushLatency.mean(TimeUnit.MILLISECONDS), eventFlushLatency.max(TimeUnit.MILLISECONDS)));

                LOGGER.info("Kafka Producer Batch Size: avg=%.2fKiB, max=%.2fKiB".formatted(
                        (kafkaProducerBatchSizeAvg.value() / 1024), (kafkaProducerBatchSizeMax.value() / 1024)));
                LOGGER.info("Kafka Producer Queue Time: avg=%.2fms, max=%.2fms".formatted(
                        kafkaProducerQueueTimeAvg.value(), kafkaProducerQueueTimeMax.value()));
            } catch (MeterNotFoundException e) {
                LOGGER.warn("Meters not ready yet");
            }
        }
    }

}
