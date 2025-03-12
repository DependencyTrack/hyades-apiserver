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
package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class ProcessorManagerTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Rule
    public KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.9.0")
            // TODO: Remove this when Kafka >= 3.9.1 is available.
            //   * https://github.com/testcontainers/testcontainers-java/issues/9506#issuecomment-2463504967
            //   * https://issues.apache.org/jira/browse/KAFKA-18281
            .withEnv("KAFKA_LISTENERS", "PLAINTEXT://:9092,BROKER://:9093,CONTROLLER://:9094");

    private AdminClient adminClient;
    private Producer<String, String> producer;

    @Before
    public void setUp() {
        adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()));
        producer = new KafkaProducer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()),
                Map.entry(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class),
                Map.entry(VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class)
        ));

        environmentVariables.set("KAFKA_BOOTSTRAP_SERVERS", kafkaContainer.getBootstrapServers());
    }

    @After
    public void tearDown() {
        if (adminClient != null) {
            adminClient.close();
        }
        if (producer != null) {
            producer.close();
        }
    }

    @Test
    public void testSingleRecordProcessor() throws Exception {
        final var inputTopic = new Topic<>("input", Serdes.String(), Serdes.String());
        adminClient.createTopics(List.of(new NewTopic(inputTopic.name(), 3, (short) 1))).all().get();

        final var recordsProcessed = new AtomicInteger(0);

        environmentVariables.set("KAFKA_PROCESSOR_FOO_PROCESSING_ORDER", "key");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_MAX_CONCURRENCY", "5");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_CONSUMER_AUTO_OFFSET_RESET", "earliest");

        final Processor<String, String> processor =
                record -> recordsProcessed.incrementAndGet();

        try (final var processorManager = new ProcessorManager()) {
            processorManager.registerProcessor("foo", inputTopic, processor);

            for (int i = 0; i < 100; i++) {
                producer.send(new ProducerRecord<>("input", "foo" + i, "bar" + i));
            }

            processorManager.startAll();

            await("Record Processing")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(recordsProcessed).hasValue(100));
        }
    }

    @Test
    public void testSingleRecordProcessorRetry() throws Exception {
        final var inputTopic = new Topic<>("input", Serdes.String(), Serdes.String());
        adminClient.createTopics(List.of(new NewTopic(inputTopic.name(), 3, (short) 1))).all().get();

        final var attemptsCounter = new AtomicInteger(0);

        final var objectSpy = spy(new Object());
        when(objectSpy.toString())
                .thenThrow(new RuntimeException(new TimeoutException()))
                .thenThrow(new RuntimeException(new TimeoutException()))
                .thenThrow(new RuntimeException(new TimeoutException()))
                .thenReturn("done");

        final Processor<String, String> processor = record -> {
            attemptsCounter.incrementAndGet();
            var ignored = objectSpy.toString();
        };

        environmentVariables.set("KAFKA_PROCESSOR_FOO_RETRY_INITIAL_DELAY_MS", "5");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_RETRY_MULTIPLIER", "1");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_RETRY_MAX_DELAY_MS", "10");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_CONSUMER_AUTO_OFFSET_RESET", "earliest");

        try (final var processorManager = new ProcessorManager()) {
            processorManager.registerProcessor("foo", inputTopic, processor);

            producer.send(new ProducerRecord<>("input", "foo", "bar"));

            processorManager.startAll();

            await("Record Processing")
                    .atMost(Duration.ofSeconds(15))
                    .untilAsserted(() -> assertThat(attemptsCounter).hasValue(4));
        }
    }

    @Test
    public void testBatchProcessor() throws Exception {
        final var inputTopic = new Topic<>("input", Serdes.String(), Serdes.String());
        adminClient.createTopics(List.of(new NewTopic(inputTopic.name(), 3, (short) 1))).all().get();

        final var recordsProcessed = new AtomicInteger(0);
        final var actualBatchSizes = new ConcurrentLinkedQueue<>();

        environmentVariables.set("KAFKA_PROCESSOR_FOO_PROCESSING_ORDER", "key");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_MAX_BATCH_SIZE", "100");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_CONSUMER_AUTO_OFFSET_RESET", "earliest");

        final BatchProcessor<String, String> recordProcessor = records -> {
            recordsProcessed.addAndGet(records.size());
            actualBatchSizes.add(records.size());
        };

        try (final var processorManager = new ProcessorManager()) {
            processorManager.registerBatchProcessor("foo", inputTopic, recordProcessor);

            for (int i = 0; i < 1_000; i++) {
                producer.send(new ProducerRecord<>("input", "foo" + i, "bar" + i));
            }

            processorManager.startAll();

            await("Record Processing")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(recordsProcessed).hasValue(1_000));

            assertThat(actualBatchSizes).containsOnly(100);
        }
    }

    @Test
    public void testWithMaxConcurrencyMatchingPartitionCount() throws Exception {
        final var inputTopic = new Topic<>("input", Serdes.String(), Serdes.String());
        adminClient.createTopics(List.of(new NewTopic(inputTopic.name(), 12, (short) 1))).all().get();

        environmentVariables.set("KAFKA_PROCESSOR_FOO_PROCESSING_ORDER", "partition");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_MAX_CONCURRENCY", "-1");
        environmentVariables.set("KAFKA_PROCESSOR_FOO_CONSUMER_AUTO_OFFSET_RESET", "earliest");

        final var threadNames = new ArrayBlockingQueue<String>(100);
        final Processor<String, String> processor = record -> {
            threadNames.add(Thread.currentThread().getName());
        };

        try (final var processorManager = new ProcessorManager()) {
            processorManager.registerProcessor("foo", inputTopic, processor);

            for (int i = 0; i < 100; i++) {
                producer.send(new ProducerRecord<>("input", "foo" + i, "bar" + i));
            }

            processorManager.startAll();

            await("Record Processing")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(threadNames).hasSize(100));

            assertThat(threadNames.stream().distinct()).hasSize(12);
        }
    }

    @Test
    public void testStartAllWithMissingTopics() throws Exception {
        final var inputTopicA = new Topic<>("input-a", Serdes.String(), Serdes.String());
        final var inputTopicB = new Topic<>("input-b", Serdes.String(), Serdes.String());
        adminClient.createTopics(List.of(new NewTopic(inputTopicA.name(), 3, (short) 1))).all().get();

        final Processor<String, String> processor = record -> {
        };

        try (final var processorManager = new ProcessorManager()) {
            processorManager.registerProcessor("a", inputTopicA, processor);
            processorManager.registerProcessor("b", inputTopicB, processor);

            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(processorManager::startAll)
                    .withMessage("""
                            Existence of 1 topic(s) could not be verified: \
                            [{topic=input-b, error=org.apache.kafka.common.errors.UnknownTopicOrPartitionException: \
                            This server does not host this topic-partition.}]""");
        }
    }

    @Test
    public void testProbeHealth() throws Exception {
        final var inputTopic = new Topic<>("input", Serdes.String(), Serdes.String());
        adminClient.createTopics(List.of(new NewTopic(inputTopic.name(), 3, (short) 1))).all().get();

        final Processor<String, String> processor = record -> {
        };

        try (final var processorManager = new ProcessorManager()) {
            processorManager.registerProcessor("foo", inputTopic, processor);

            {
                final HealthCheckResponse healthCheckResponse = processorManager.probeHealth();
                assertThat(healthCheckResponse.getName()).isEqualTo("kafka-processors");
                assertThat(healthCheckResponse.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
                assertThat(healthCheckResponse.getData()).isPresent();
                assertThatJson(healthCheckResponse.getData().get())
                        .isEqualTo("""
                                {
                                  "foo": "UP"
                                }
                                """);
            }

            processorManager.startAll();

            {
                final HealthCheckResponse healthCheckResponse = processorManager.probeHealth();
                assertThat(healthCheckResponse.getName()).isEqualTo("kafka-processors");
                assertThat(healthCheckResponse.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
                assertThat(healthCheckResponse.getData()).isPresent();
                assertThatJson(healthCheckResponse.getData().get())
                        .isEqualTo("""
                                {
                                  "foo": "UP"
                                }
                                """);
            }

            processorManager.close();

            {
                final HealthCheckResponse healthCheckResponse = processorManager.probeHealth();
                assertThat(healthCheckResponse.getName()).isEqualTo("kafka-processors");
                assertThat(healthCheckResponse.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
                assertThat(healthCheckResponse.getData()).isPresent();
                assertThatJson(healthCheckResponse.getData().get())
                        .isEqualTo("""
                                {
                                  "foo": "DOWN"
                                }
                                """);
            }
        }
    }

}