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

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.MockConfigRegistry;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.PublishContext;
import org.dependencytrack.proto.notification.v1.Notification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

import java.util.List;
import java.util.Map;

import static org.dependencytrack.notification.publishing.kafka.KafkaNotificationPublisherConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.dependencytrack.notification.publishing.kafka.KafkaNotificationPublisherConfigs.CLIENT_ID_CONFIG;

@Testcontainers
class KafkaNotificationPublisherTest {

    @Container
    private final KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.9.1");

    @BeforeEach
    void beforeEach() throws Exception {
        try (final var adminClient = AdminClient.create(Map.of(
                AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.createTopics(List.of(new NewTopic("foo", 1, (short) 1))).all().get();
        }
    }

    @Test
    void test() throws Exception {
        final var notification = Notification.newBuilder().build();

        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG.name(), kafkaContainer.getBootstrapServers()),
                Map.entry(CLIENT_ID_CONFIG.name(), "foobar")));

        try (final var publisherFactory = new KafkaNotificationPublisherFactory()) {
            publisherFactory.init(new ExtensionContext(configRegistry));

            try (final NotificationPublisher publisher = publisherFactory.create()) {
                publisher.publish(new PublishContext("foo", null, null), notification);
            }
        }
    }

}