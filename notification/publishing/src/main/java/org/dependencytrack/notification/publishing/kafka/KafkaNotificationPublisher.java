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
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
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
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.notification.proto.v1.BomValidationFailedSubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.UserSubject;
import org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.apache.kafka.clients.producer.ProducerConfig.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.COMPRESSION_TYPE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;

/**
 * @since 5.7.0
 */
final class KafkaNotificationPublisher implements NotificationPublisher {

    private static final Logger LOGGER = LoggerFactory.getLogger(KafkaNotificationPublisher.class);

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

        final String recordKey;
        try {
            recordKey = extractKey(notification);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to extract record key from notification", e);
        }

        final var producerRecord = new ProducerRecord<>(
                ruleConfig.getTopicName(),
                /* partition */ null,
                recordKey,
                notificationContent,
                new RecordHeaders()
                        .add("content-type", mimeType.getBytes()));

        try {
            producer.send(producerRecord).get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof final RetriableException re) {
                throw new RetryablePublishException("Failed to send record with retryable cause", re);
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

        if (ruleConfig.getProducerConfigs() != null) {
            for (final String customConfig : ruleConfig.getProducerConfigs()) {
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
                String.join(",", ruleConfig.getBootstrapServers()));
        producerCfg.setProperty(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerCfg.setProperty(VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        producerCfg.setProperty(ENABLE_IDEMPOTENCE_CONFIG, "true");
        producerCfg.setProperty(COMPRESSION_TYPE_CONFIG, "snappy");

        return producerCache.get(producerCfg, KafkaProducer::new);
    }

    private static @Nullable String extractKey(Notification notification) throws InvalidProtocolBufferException {
        return switch (notification.getGroup()) {
            case GROUP_BOM_CONSUMED, GROUP_BOM_PROCESSED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(BomConsumedOrProcessedSubject.class));
                final var subject = notification.getSubject().unpack(BomConsumedOrProcessedSubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_BOM_PROCESSING_FAILED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(BomProcessingFailedSubject.class));
                final var subject = notification.getSubject().unpack(BomProcessingFailedSubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_BOM_VALIDATION_FAILED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(BomValidationFailedSubject.class));
                final var subject = notification.getSubject().unpack(BomValidationFailedSubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_NEW_VULNERABILITY -> {
                requireSubjectOfTypeAnyOf(notification, List.of(NewVulnerabilitySubject.class));
                final var subject = notification.getSubject().unpack(NewVulnerabilitySubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> {
                requireSubjectOfTypeAnyOf(notification, List.of(NewVulnerableDependencySubject.class));
                final var subject = notification.getSubject().unpack(NewVulnerableDependencySubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_POLICY_VIOLATION -> {
                requireSubjectOfTypeAnyOf(notification, List.of(PolicyViolationSubject.class));
                final var subject = notification.getSubject().unpack(PolicyViolationSubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_PROJECT_AUDIT_CHANGE -> {
                final Class<? extends Message> matchingSubject = requireSubjectOfTypeAnyOf(notification, List.of(
                        PolicyViolationAnalysisDecisionChangeSubject.class,
                        VulnerabilityAnalysisDecisionChangeSubject.class));

                if (matchingSubject == PolicyViolationAnalysisDecisionChangeSubject.class) {
                    final var subject = notification.getSubject().unpack(PolicyViolationAnalysisDecisionChangeSubject.class);
                    yield subject.getProject().getUuid();
                } else {
                    final var subject = notification.getSubject().unpack(VulnerabilityAnalysisDecisionChangeSubject.class);
                    yield subject.getProject().getUuid();
                }
            }
            case GROUP_PROJECT_CREATED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(Project.class));
                final var subject = notification.getSubject().unpack(Project.class);
                yield subject.getUuid();
            }
            case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> {
                requireSubjectOfTypeAnyOf(notification, List.of(ProjectVulnAnalysisCompleteSubject.class));
                final var subject = notification.getSubject().unpack(ProjectVulnAnalysisCompleteSubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_VEX_CONSUMED, GROUP_VEX_PROCESSED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(VexConsumedOrProcessedSubject.class));
                final var subject = notification.getSubject().unpack(VexConsumedOrProcessedSubject.class);
                yield subject.getProject().getUuid();
            }
            case GROUP_USER_CREATED, GROUP_USER_DELETED -> {
                requireSubjectOfTypeAnyOf(notification, List.of(UserSubject.class));
                final var subject = notification.getSubject().unpack(UserSubject.class);
                yield subject.getUsername();
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

    private static Class<? extends Message> requireSubjectOfTypeAnyOf(
            Notification notification,
            Collection<Class<? extends Message>> subjectClasses) {
        if (!notification.hasSubject()) {
            throw new IllegalArgumentException(
                    "Expected subject of type matching any of %s, but notification has no subject".formatted(subjectClasses));
        }

        return subjectClasses.stream()
                .filter(notification.getSubject()::is).findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Expected subject of type matching any of %s, but is %s".formatted(
                                subjectClasses, notification.getSubject().getTypeUrl())));
    }

}
