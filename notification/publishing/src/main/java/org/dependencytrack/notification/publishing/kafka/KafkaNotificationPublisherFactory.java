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
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Properties;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public final class KafkaNotificationPublisherFactory implements NotificationPublisherFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(KafkaNotificationPublisherFactory.class);

    private @Nullable Cache<Properties, KafkaProducer<String, byte[]>> producerCache;

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
        producerCache = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(5))
                .<Properties, KafkaProducer<String, byte[]>>removalListener(
                        (props, producer, cause) -> {
                            if (producer != null) {
                                LOGGER.debug("Closing producer due to removal from cache with cause: {}", cause);
                                producer.close(Duration.ofSeconds(15));
                            }
                        })
                .build();
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(producerCache, "producerCache must not be null");
        return new KafkaNotificationPublisher(producerCache);
    }

    @Override
    public RuntimeConfigSpec ruleConfigSpec() {
        final var defaultConfig = new KafkaNotificationRuleConfig()
                .withBootstrapServers(Set.of("localhost:9092"))
                .withTopicName("dependencytrack-notifications")
                .withPublishProtobuf(true);

        return RuntimeConfigSpec.of(defaultConfig);
    }

    @Override
    public void close() {
        if (producerCache != null) {
            producerCache.invalidateAll();
        }
    }

}
