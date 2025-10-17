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

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisherFactory;

import java.util.Properties;

import static org.dependencytrack.notification.publishing.kafka.KafkaNotificationPublisherConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.dependencytrack.notification.publishing.kafka.KafkaNotificationPublisherConfigs.CLIENT_ID_CONFIG;

/**
 * @since 5.7.0
 */
final class KafkaNotificationPublisherFactory implements NotificationPublisherFactory {

    private KafkaProducer<String, byte[]> kafkaProducer;

    @Override
    public String extensionName() {
        return "kafka";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return KafkaNotificationPublisher.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public void init(final ExtensionContext ctx) {
        // TODO: Make bootstrap servers configurable via notification rules.
        // TODO: Hardcode client ID?
        final var producerCfg = new Properties();
        producerCfg.setProperty(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,
                ctx.configRegistry().getValue(BOOTSTRAP_SERVERS_CONFIG));
        producerCfg.setProperty(
                ProducerConfig.CLIENT_ID_CONFIG,
                ctx.configRegistry().getValue(CLIENT_ID_CONFIG));
        producerCfg.setProperty(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        producerCfg.setProperty(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerCfg.setProperty(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());

        kafkaProducer = new KafkaProducer<>(producerCfg);
    }

    @Override
    public NotificationPublisher create() {
        return new KafkaNotificationPublisher(kafkaProducer);
    }

    @Override
    public String defaultTemplate() {
        return null;
    }

    @Override
    public void close() {
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
    }

}
