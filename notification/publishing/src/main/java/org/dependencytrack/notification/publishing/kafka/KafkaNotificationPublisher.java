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

import com.github.benmanes.caffeine.cache.Cache;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationRuleConfig;
import org.dependencytrack.notification.api.publishing.PublishContext;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.util.Properties;
import java.util.concurrent.ExecutionException;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.publishing.kafka.KafkaNotificationPublisherRuleConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.dependencytrack.notification.publishing.kafka.KafkaNotificationPublisherRuleConfigs.CLIENT_ID_CONFIG;

/**
 * @since 5.7.0
 */
final class KafkaNotificationPublisher implements NotificationPublisher {

    private final Cache<Properties, KafkaProducer<String, byte[]>> producerCache;

    KafkaNotificationPublisher(Cache<Properties, KafkaProducer<String, byte[]>> producerCache) {
        this.producerCache = producerCache;
    }

    @Override
    public void publish(PublishContext ctx, Notification notification) {
        requireNonNull(ctx, "ctx must not be null");
        requireNonNull(notification, "notification must not be null");

        final KafkaProducer<String, byte[]> producer = getProducer(ctx.ruleConfig());

        final String topicName = ctx.destination();
        if (topicName == null || topicName.isEmpty()) {
            throw new IllegalStateException("No destination (topic name) configured");
        }

        final RenderedTemplate renderedTemplate = ctx.templateRenderer().render(notification);

        final String mimeType;
        final byte[] notificationContent;
        if (renderedTemplate != null) {
            mimeType = renderedTemplate.mimeType();
            notificationContent = renderedTemplate.content().getBytes();
        } else {
            // https://protobuf.dev/reference/protobuf/mime-types/
            mimeType = "application/protobuf";
            notificationContent = notification.toByteArray();
        }

        // TODO: Extract key from notification.
        final var producerRecord = new ProducerRecord<>(
                topicName,
                /* partition */ null,
                "TODO",
                notificationContent,
                new RecordHeaders()
                        .add("content-type", mimeType.getBytes()));

        try {
            producer.send(producerRecord).get();
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failed to send record", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending record", e);
        }
    }

    private KafkaProducer<String, byte[]> getProducer(NotificationRuleConfig ruleConfig) {
        final var producerCfg = new Properties();
        producerCfg.setProperty(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,
                ruleConfig.getValue(BOOTSTRAP_SERVERS_CONFIG));
        producerCfg.setProperty(
                ProducerConfig.CLIENT_ID_CONFIG,
                ruleConfig.getOptionalValue(CLIENT_ID_CONFIG).orElse("foo"));
        producerCfg.setProperty(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        producerCfg.setProperty(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerCfg.setProperty(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());

        return producerCache.get(producerCfg, KafkaProducer::new);
    }

}
