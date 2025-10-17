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
import org.apache.kafka.common.errors.RetriableException;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * @since 5.7.0
 */
final class KafkaNotificationPublisher implements NotificationPublisher {

    private final Cache<Properties, KafkaProducer<String, byte[]>> producerCache;

    KafkaNotificationPublisher(Cache<Properties, KafkaProducer<String, byte[]>> producerCache) {
        this.producerCache = producerCache;
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) {
        final var ruleConfig = ctx.ruleConfig(KafkaNotificationRuleConfig.class);

        final KafkaProducer<String, byte[]> producer = getProducer(ruleConfig);

        final RenderedNotificationTemplate renderedTemplate = ctx.templateRenderer().render(notification);

        final String mimeType;
        final byte[] notificationContent;
        if (ruleConfig.getPublishProtobuf()) {
            // https://protobuf.dev/reference/protobuf/mime-types/
            mimeType = "application/protobuf";
            notificationContent = notification.toByteArray();
        } else if (renderedTemplate != null) {
            mimeType = renderedTemplate.mimeType();
            notificationContent = renderedTemplate.content().getBytes();
        } else {
            throw new IllegalStateException("No template configured");
        }

        // TODO: Extract key from notification.
        final var producerRecord = new ProducerRecord<>(
                ruleConfig.getTopicName(),
                /* partition */ null,
                "TODO",
                notificationContent,
                new RecordHeaders()
                        .add("content-type", mimeType.getBytes()));

        try {
            producer.send(producerRecord).get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof final RetriableException retriableException) {
                throw new RetryablePublishException("Failed to send record with retryable cause", e);
            }

            throw new IllegalStateException("Failed to send record", e);
        } catch (TimeoutException e) {
            throw new RetryablePublishException("Timed out while waiting for record to be acknowledged", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending record", e);
        }
    }

    private KafkaProducer<String, byte[]> getProducer(KafkaNotificationRuleConfig ruleConfig) {
        final var producerCfg = new Properties();
        producerCfg.setProperty(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,
                String.join(",", ruleConfig.getBootstrapServers()));
        producerCfg.setProperty(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        producerCfg.setProperty(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerCfg.setProperty(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());

        return producerCache.get(producerCfg, KafkaProducer::new);
    }

}
