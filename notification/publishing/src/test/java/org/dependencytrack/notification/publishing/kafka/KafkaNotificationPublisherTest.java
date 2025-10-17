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
package org.dependencytrack.notification.publishing.kafka;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.junit.jupiter.api.BeforeEach;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class KafkaNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @Container
    private final KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:4.1.1");

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new KafkaNotificationPublisherFactory();
    }

    @Override
    protected void customizeRuleConfig(RuntimeConfig ruleConfig) {
        final var kafkaRuleConfig = (KafkaNotificationRuleConfig) ruleConfig;
        kafkaRuleConfig.setBootstrapServers(Set.of(kafkaContainer.getBootstrapServers()));
    }

    @BeforeEach
    @Override
    protected void beforeEach() throws Exception {
        try (final var adminClient = AdminClient.create(Map.of(
                CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.createTopics(List.of(new NewTopic("dependencytrack-notifications", 1, (short) 1))).all().get();
        }

        super.beforeEach();
    }

    @Override
    protected void validateBomConsumedNotificationPublish(Notification notification) throws Exception {
        final ConsumerRecord<String, byte[]> record = pollNotificationRecord();
        assertThat(record.key()).isEqualTo("TODO");
        assertThat(record.headers()).containsExactly(new RecordHeader("content-type", "application/protobuf".getBytes()));
        assertThat(Notification.parseFrom(record.value())).isEqualTo(notification);
    }

    @Override
    protected void validateBomProcessingFailedNotificationPublish(Notification notification) throws Exception {
        final ConsumerRecord<String, byte[]> record = pollNotificationRecord();
        assertThat(record.key()).isEqualTo("TODO");
        assertThat(record.headers()).containsExactly(new RecordHeader("content-type", "application/protobuf".getBytes()));
        assertThat(Notification.parseFrom(record.value())).isEqualTo(notification);
    }

    @Override
    protected void validateBomValidationFailedNotificationPublish(Notification notification) throws Exception {
        final ConsumerRecord<String, byte[]> record = pollNotificationRecord();
        assertThat(record.key()).isEqualTo("TODO");
        assertThat(record.headers()).containsExactly(new RecordHeader("content-type", "application/protobuf".getBytes()));
        assertThat(Notification.parseFrom(record.value())).isEqualTo(notification);
    }

    @Override
    protected void validateNewVulnerabilityNotificationPublish(Notification notification) throws Exception {
        final ConsumerRecord<String, byte[]> record = pollNotificationRecord();
        assertThat(record.key()).isEqualTo("TODO");
        assertThat(record.headers()).containsExactly(new RecordHeader("content-type", "application/protobuf".getBytes()));
        assertThat(Notification.parseFrom(record.value())).isEqualTo(notification);
    }

    @Override
    protected void validateNewVulnerableDependencyNotificationPublish(Notification notification) throws Exception {
        final ConsumerRecord<String, byte[]> record = pollNotificationRecord();
        assertThat(record.key()).isEqualTo("TODO");
        assertThat(record.headers()).containsExactly(new RecordHeader("content-type", "application/protobuf".getBytes()));
        assertThat(Notification.parseFrom(record.value())).isEqualTo(notification);
    }

    private ConsumerRecord<String, byte[]> pollNotificationRecord() {
        try (final var consumer = new KafkaConsumer<String, byte[]>(Map.ofEntries(
                Map.entry(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()),
                Map.entry(ConsumerConfig.GROUP_ID_CONFIG, "test-group"),
                Map.entry(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest"),
                Map.entry(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName()),
                Map.entry(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName())))) {
            consumer.subscribe(List.of("dependencytrack-notifications"));

            final ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(1));
            assertThat(records).hasSize(1);

            return records.iterator().next();
        }
    }

}