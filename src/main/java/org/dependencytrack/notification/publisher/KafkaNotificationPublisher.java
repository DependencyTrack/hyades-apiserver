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
package org.dependencytrack.notification.publisher;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.proto.notification.v1.Notification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static org.apache.kafka.clients.producer.ProducerConfig.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG;

public class KafkaNotificationPublisher implements NotificationPublisher, Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(KafkaNotificationPublisher.class);
    private static final String KAFKA_PRODUCER_CONFIG_PREFIX = "kafka.producer.";

    private final Cache<Properties, KafkaProducer<String, byte[]>> producerCache;

    public KafkaNotificationPublisher() {
        producerCache = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(5))
                .<Properties, KafkaProducer<String, byte[]>>evictionListener(
                        (producerConfig, producer, cause) -> {
                            if (producer != null) {
                                LOGGER.debug("Closing producer due to cache eviction with reason: {}", cause);
                                producer.close();
                            }
                        })
                .build();
    }

    @Override
    public void publish(final Context ctx, final Notification notification) {
        if (ctx.config() == null) {
            throw new IllegalStateException("No config provided");
        }

        final String topicName = ctx.config().getString("destination", null);
        if (topicName == null) {
            throw new IllegalStateException("No destination (topic name) configured");
        }

        final Properties producerConfig = buildProducerConfig(ctx.config());

        // Producers are closed as part of cache eviction.
        //noinspection resource
        final KafkaProducer<String, byte[]> producer = producerCache.asMap()
                .computeIfAbsent(producerConfig, KafkaProducer::new);

        // TODO: Pick a record key based on notification type (i.e. project UUID).

        final var producerRecord = new ProducerRecord<String, byte[]>(
                topicName, null, notification.toByteArray());
        final Future<?> sendFuture = producer.send(producerRecord);

        if (!ctx.config().getBoolean("blocking", true)) {
            return;
        }

        try {
            sendFuture.get();
        } catch (ExecutionException e) {
            throw new RuntimeException("Failed to send notification record", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting for record to be acknowledged", e);
        }
    }

    private Properties buildProducerConfig(final JsonObject publisherConfig) {
        final var producerConfig = new Properties();

        for (final Map.Entry<String, JsonValue> entry : publisherConfig.entrySet()) {
            if (!entry.getKey().startsWith(KAFKA_PRODUCER_CONFIG_PREFIX)) {
                continue;
            }

            final String configName = entry.getKey().substring(KAFKA_PRODUCER_CONFIG_PREFIX.length());
            if (!ProducerConfig.configNames().contains(configName)) {
                LOGGER.warn("Ignoring unknown producer config: {}", configName);
                continue;
            }

            if (entry.getValue() instanceof final JsonString configValueJsonString) {
                producerConfig.put(configName, configValueJsonString.getString());
            } else {
                LOGGER.warn("Ignoring producer config {} of unexpected type {}", configName, entry.getValue().getClass());
            }
        }

        producerConfig.put(
                BOOTSTRAP_SERVERS_CONFIG,
                publisherConfig.getString(KAFKA_PRODUCER_CONFIG_PREFIX + BOOTSTRAP_SERVERS_CONFIG));
        producerConfig.put(
                CLIENT_ID_CONFIG,
                publisherConfig.getString(KAFKA_PRODUCER_CONFIG_PREFIX + CLIENT_ID_CONFIG, "dtrack-notification-publisher"));
        producerConfig.put(
                ENABLE_IDEMPOTENCE_CONFIG,
                "true");

        producerConfig.put(
                ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG,
                StringSerializer.class.getName());
        producerConfig.put(
                ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,
                ByteArraySerializer.class.getName());

        return producerConfig;
    }

    @Override
    public void close() throws IOException {
        producerCache.invalidateAll();
    }

}
