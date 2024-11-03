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
package org.dependencytrack.event.kafka.consumer;

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.event.kafka.consumer.KafkaBatchConsumer.State;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.AUTO_OFFSET_RESET_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;

public class KafkaBatchConsumerTest {

    @Rule
    public KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.8.0");

    private KafkaConsumer<String, String> kafkaConsumer;
    private KafkaProducer<String, String> kafkaProducer;
    private AdminClient adminClient;

    @Before
    public void before() throws Exception {
        kafkaConsumer = new KafkaConsumer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()),
                Map.entry(CLIENT_ID_CONFIG, UUID.randomUUID().toString()),
                Map.entry(GROUP_ID_CONFIG, UUID.randomUUID().toString()),
                Map.entry(KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class),
                Map.entry(VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class),
                Map.entry(ENABLE_AUTO_COMMIT_CONFIG, "false"),
                Map.entry(AUTO_OFFSET_RESET_CONFIG, "earliest")));
        kafkaProducer = new KafkaProducer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()),
                Map.entry(CLIENT_ID_CONFIG, UUID.randomUUID().toString()),
                Map.entry(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class),
                Map.entry(VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class)));

        adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()));
        adminClient.createTopics(List.of(new NewTopic("test", 3, (short) 1))).all().get();
    }

    @After
    public void after() {
        if (kafkaConsumer != null) {
            kafkaConsumer.close();
        }
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
        if (adminClient != null) {
            assertThatNoException().isThrownBy(
                    () -> adminClient.deleteTopics(List.of("test")).all().get());
            adminClient.close();
        }
    }

    @Test
    public void shouldRetryTransientFailure() throws Exception {
        final var attempts = new AtomicInteger(0);
        final var batchSizes = new ConcurrentLinkedQueue<>();

        final var consumer = new KafkaBatchConsumer<>(kafkaConsumer, Duration.ofMinutes(1), 5) {

            @Override
            protected boolean flushBatch(final List<ConsumerRecord<String, String>> consumerRecords) {
                batchSizes.add(consumerRecords.size());

                if (attempts.incrementAndGet() <= 3) {
                    throw new IllegalStateException("Technical Difficulties");
                }

                return true;
            }

        };

        kafkaConsumer.subscribe(List.of("test"), consumer);

        final var consumerThread = new Thread(consumer);
        consumerThread.start();

        for (int i = 0; i < 8; i++) {
            final RecordMetadata recordMetadata = kafkaProducer.send(new ProducerRecord<>(
                    "test", UUID.randomUUID().toString(), UUID.randomUUID().toString())).get();
            assertThat(recordMetadata).isNotNull();
        }

        await("Successful flush")
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    assertThat(batchSizes).containsExactly(5, 8, 8, 8);
                    assertThat(attempts.get()).isEqualTo(4);
                    assertThat(consumer.state()).isEqualTo(State.RUNNING);
                });

        consumer.shutdown();
        consumerThread.join();

        await("Consumer stopped")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(consumer.state()).isEqualTo(State.STOPPED));
    }

}