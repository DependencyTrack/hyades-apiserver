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
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;
import static org.apache.kafka.clients.producer.ProducerConfig.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.COMPRESSION_TYPE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;

/**
 * @since 5.7.0
 */
public final class KafkaNotificationPublisherFactory implements NotificationPublisherFactory {

    private record CachedProducer(
            Properties config,
            KafkaProducer<String, byte[]> producer) {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(KafkaNotificationPublisherFactory.class);

    private final Lock producerCacheLock = new ReentrantLock();
    private @Nullable ConfigRegistry configRegistry;
    private @Nullable CachedProducer cachedProducer;

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
    public void init(ExtensionContext ctx) {
        configRegistry = ctx.configRegistry();
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(configRegistry, "configRegistry must not be null");

        final var globalConfig = configRegistry.getRuntimeConfig(KafkaNotificationPublisherGlobalConfig.class);
        requireNonNull(globalConfig, "globalConfig must not be null");

        if (!globalConfig.getEnabled()) {
            throw new IllegalStateException("Kafka notification publisher is disabled");
        }

        final KafkaProducer<String, byte[]> kafkaProducer = getKafkaProducer(globalConfig);

        return new KafkaNotificationPublisher(kafkaProducer);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return new RuntimeConfigSpec(
                new KafkaNotificationPublisherGlobalConfig());
    }

    @Override
    public RuntimeConfigSpec ruleConfigSpec() {
        final var defaultConfig = new KafkaNotificationPublisherRuleConfig()
                .withTopicName("dependencytrack-notifications")
                .withPublishProtobuf(true);

        return new RuntimeConfigSpec(defaultConfig);
    }

    @Override
    public void close() {
        producerCacheLock.lock();
        try {
            if (cachedProducer != null) {
                cachedProducer.producer().close();
                cachedProducer = null;
            }
        } finally {
            producerCacheLock.unlock();
        }
    }

    private KafkaProducer<String, byte[]> getKafkaProducer(KafkaNotificationPublisherGlobalConfig globalConfig) {
        final var producerCfg = new Properties();

        if (globalConfig.getProducerConfigs() != null) {
            for (final String customConfig : globalConfig.getProducerConfigs()) {
                final String[] parts = customConfig.split("=", 2);
                if (parts.length != 2) {
                    LOGGER.warn("Ignoring malformed producer config: {}", customConfig);
                    continue;
                }

                final String configName = parts[0].trim();
                final String configValue = parts[1].trim();

                if (!ProducerConfig.configNames().contains(configName)) {
                    LOGGER.warn("Ignoring unrecognized producer config: {}", configName);
                    continue;
                }

                producerCfg.put(configName, configValue);
            }
        }

        producerCfg.setProperty(
                BOOTSTRAP_SERVERS_CONFIG,
                String.join(",", globalConfig.getBootstrapServers()));
        producerCfg.setProperty(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerCfg.setProperty(VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        producerCfg.setProperty(ENABLE_IDEMPOTENCE_CONFIG, "true");
        producerCfg.setProperty(COMPRESSION_TYPE_CONFIG, "snappy");

        producerCacheLock.lock();
        try {
            if (cachedProducer != null) {
                if (Objects.equals(cachedProducer.config(), producerCfg)) {
                    // NB: Publishers treat closed Kafka producers as a retryable failure.
                    LOGGER.debug("Using cached producer with matching config");
                    return cachedProducer.producer();
                }

                LOGGER.debug("Producer config has changed; Closing cached producer");
                cachedProducer.producer().close();
                cachedProducer = null;
            }

            final var producer = new KafkaProducer<String, byte[]>(producerCfg);
            cachedProducer = new CachedProducer(producerCfg, producer);
            return producer;
        } finally {
            producerCacheLock.unlock();
        }
    }

}
