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
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.proto.notification.v1.PolicyViolationSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.notification.v1.UserSubject;
import org.dependencytrack.proto.notification.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static org.apache.commons.lang3.ObjectUtils.requireNonEmpty;
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

        final String recordKey;
        try {
            recordKey = determineRecordKey(notification);
        } catch (InvalidProtocolBufferException e) {
            throw new IllegalStateException("Failed to determine Kafka record key", e);
        }

        final var producerRecord = new ProducerRecord<>(
                topicName, recordKey, notification.toByteArray());
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

    // Copied from KafkaEventConverter
    private String determineRecordKey(final Notification notification) throws InvalidProtocolBufferException {
        return switch (notification.getGroup()) {
            case GROUP_BOM_CONSUMED, GROUP_BOM_PROCESSED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(BomConsumedOrProcessedSubject.class));
                final var subject = notification.getSubject().unpack(BomConsumedOrProcessedSubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_BOM_PROCESSING_FAILED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(BomProcessingFailedSubject.class));
                final var subject = notification.getSubject().unpack(BomProcessingFailedSubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_BOM_VALIDATION_FAILED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(BomValidationFailedSubject.class));
                final var subject = notification.getSubject().unpack(BomValidationFailedSubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_NEW_VULNERABILITY -> {
                requireSubjectOfTypeAnyOf(notification, List.of(NewVulnerabilitySubject.class));
                final var subject = notification.getSubject().unpack(NewVulnerabilitySubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> {
                requireSubjectOfTypeAnyOf(notification, List.of(NewVulnerableDependencySubject.class));
                final var subject = notification.getSubject().unpack(NewVulnerableDependencySubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_POLICY_VIOLATION -> {
                requireSubjectOfTypeAnyOf(notification, List.of(PolicyViolationSubject.class));
                final var subject = notification.getSubject().unpack(PolicyViolationSubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_PROJECT_AUDIT_CHANGE -> {
                final Class<? extends Message> matchingSubject = requireSubjectOfTypeAnyOf(notification, List.of(
                        PolicyViolationAnalysisDecisionChangeSubject.class,
                        VulnerabilityAnalysisDecisionChangeSubject.class
                ));

                if (matchingSubject == PolicyViolationAnalysisDecisionChangeSubject.class) {
                    final var subject = notification.getSubject().unpack(PolicyViolationAnalysisDecisionChangeSubject.class);
                    yield requireNonEmpty(subject.getProject().getUuid());
                } else {
                    final var subject = notification.getSubject().unpack(VulnerabilityAnalysisDecisionChangeSubject.class);
                    yield requireNonEmpty(subject.getProject().getUuid());
                }
            }
            case GROUP_PROJECT_CREATED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(Project.class));
                final var subject = notification.getSubject().unpack(Project.class);
                yield requireNonEmpty(subject.getUuid());
            }
            case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> {
                requireSubjectOfTypeAnyOf(notification, List.of(ProjectVulnAnalysisCompleteSubject.class));
                final var subject = notification.getSubject().unpack(ProjectVulnAnalysisCompleteSubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_VEX_CONSUMED, GROUP_VEX_PROCESSED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(VexConsumedOrProcessedSubject.class));
                final var subject = notification.getSubject().unpack(VexConsumedOrProcessedSubject.class);
                yield requireNonEmpty(subject.getProject().getUuid());
            }
            case GROUP_USER_CREATED, GROUP_USER_DELETED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(UserSubject.class));
                final var subject = notification.getSubject().unpack(UserSubject.class);
                yield requireNonEmpty(subject.getUsername());
            }
            case GROUP_ANALYZER, GROUP_CONFIGURATION, GROUP_DATASOURCE_MIRRORING,
                 GROUP_FILE_SYSTEM, GROUP_INTEGRATION, GROUP_REPOSITORY -> null;
            case GROUP_UNSPECIFIED, UNRECOGNIZED -> throw new IllegalArgumentException("""
                    Unable to determine record key because the notification does not \
                    specify a notification group: %s""".formatted(notification.getGroup()));
            // NB: The lack of a default case is intentional. This way, the compiler will fail
            // the build when new groups are added, and we don't have a case for it :)
        };
    }

    // Copied from KafkaEventConverter
    private static Class<? extends Message> requireSubjectOfTypeAnyOf(final Notification notification,
                                                                      final Collection<Class<? extends Message>> subjectClasses) {
        if (!notification.hasSubject()) {
            throw new IllegalArgumentException("Expected subject of type matching any of %s, but notification has no subject"
                    .formatted(subjectClasses));
        }

        return subjectClasses.stream()
                .filter(notification.getSubject()::is).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Expected subject of type matching any of %s, but is %s"
                        .formatted(subjectClasses, notification.getSubject().getTypeUrl())));
    }

}
