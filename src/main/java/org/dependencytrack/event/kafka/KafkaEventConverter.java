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
package org.dependencytrack.event.kafka;

import alpine.event.framework.Event;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.CsafMirrorEvent;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.dependencytrack.NotificationModelConverter;
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
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisCommand;
import org.dependencytrack.proto.vulnanalysis.v1.Component;
import org.dependencytrack.proto.vulnanalysis.v1.ScanCommand;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.apache.commons.lang3.ObjectUtils.requireNonEmpty;

/**
 * Utility class to convert {@link Event}s and {@link alpine.notification.Notification}s
 * to {@link KafkaEvent}s.
 */
public final class KafkaEventConverter {

    private KafkaEventConverter() {
    }

    static KafkaEvent<?, ?> convert(final Event event) {
        return switch (event) {
            case ComponentRepositoryMetaAnalysisEvent e -> convert(e);
            case ComponentVulnerabilityAnalysisEvent e -> convert(e);
            case GitHubAdvisoryMirrorEvent e -> convert(e);
            case NistMirrorEvent e -> convert(e);
            case OsvMirrorEvent e -> convert(e);
            case CsafMirrorEvent e -> convert(e);
            case EpssMirrorEvent e -> convert(e);
            default -> throw new IllegalArgumentException("Unable to convert event " + event);
        };
    }

    public static KafkaEvent<?, ?> convert(final alpine.notification.Notification notification) {
        final Notification protoNotification = NotificationModelConverter.convert(notification);
        return convert(protoNotification);
    }

    public static KafkaEvent<?, ?> convert(final Notification notification) {
        final Topic<String, Notification> topic = extractDestinationTopic(notification);

        final String recordKey;
        try {
            recordKey = extractEventKey(notification);
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }

        return new KafkaEvent<>(topic, recordKey, notification);
    }

    static List<KafkaEvent<?, ?>> convertAllNotificationProtos(final Collection<Notification> notifications) {
        final var kafkaEvents = new ArrayList<KafkaEvent<?, ?>>(notifications.size());
        for (final Notification notification : notifications) {
            kafkaEvents.add(convert(notification));
        }

        return kafkaEvents;
    }

    static KafkaEvent<ScanKey, ScanCommand> convert(final ComponentVulnerabilityAnalysisEvent event) {
        final var componentBuilder = Component.newBuilder()
                .setUuid(event.uuid().toString());
        Optional.ofNullable(event.cpe()).ifPresent(componentBuilder::setCpe);
        Optional.ofNullable(event.purl()).ifPresent(componentBuilder::setPurl);
        Optional.ofNullable(event.swidTagId()).ifPresent(componentBuilder::setSwidTagId);
        Optional.ofNullable(event.internal()).ifPresent(componentBuilder::setInternal);

        final var scanKey = ScanKey.newBuilder()
                .setScanToken(event.token().toString())
                .setComponentUuid(event.uuid().toString())
                .build();

        final var scanCommand = ScanCommand.newBuilder()
                .setComponent(componentBuilder)
                .build();

        return new KafkaEvent<>(
                KafkaTopics.VULN_ANALYSIS_COMMAND,
                scanKey, scanCommand,
                Map.of(KafkaEventHeaders.VULN_ANALYSIS_LEVEL, event.level().name(),
                        KafkaEventHeaders.IS_NEW_COMPONENT, String.valueOf(event.isNewComponent()))
        );
    }

    static KafkaEvent<String, AnalysisCommand> convert(final ComponentRepositoryMetaAnalysisEvent event) {
        if (event == null || event.purlCoordinates() == null) {
            return null;
        }

        final var componentBuilder = org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                .setPurl(event.purlCoordinates());
        Optional.ofNullable(event.internal()).ifPresent(componentBuilder::setInternal);
        Optional.ofNullable(event.componentUuid()).map(UUID::toString).ifPresent(componentBuilder::setUuid);

        final var analysisCommand = AnalysisCommand.newBuilder()
                .setComponent(componentBuilder)
                .setFetchMeta(event.fetchMeta())
                .build();

        return new KafkaEvent<>(KafkaTopics.REPO_META_ANALYSIS_COMMAND, event.purlCoordinates(), analysisCommand, null);
    }

    static KafkaEvent<String, String> convert(final GitHubAdvisoryMirrorEvent ignored) {
        final String key = Vulnerability.Source.GITHUB.name();
        return new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, key, null);
    }

    static KafkaEvent<String, String> convert(final NistMirrorEvent ignored) {
        final String key = Vulnerability.Source.NVD.name();
        return new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, key, null);
    }

    static KafkaEvent<String, String> convert(final OsvMirrorEvent event) {
        final String key = Vulnerability.Source.OSV.name();
        final String value = event.ecosystem();
        return new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, key, value);
    }

    static KafkaEvent<String, String> convert(final CsafMirrorEvent event) {
        final String key = Vulnerability.Source.CSAF.name();
        return new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, key, null);
    }

    static KafkaEvent<String, String> convert(final EpssMirrorEvent ignored) {
        return new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, "EPSS", null);
    }

    private static Topic<String, Notification> extractDestinationTopic(final Notification notification) {
        return switch (notification.getGroup()) {
            case GROUP_ANALYZER -> KafkaTopics.NOTIFICATION_ANALYZER;
            case GROUP_BOM_CONSUMED, GROUP_BOM_PROCESSED, GROUP_BOM_PROCESSING_FAILED, GROUP_BOM_VALIDATION_FAILED -> KafkaTopics.NOTIFICATION_BOM;
            case GROUP_CONFIGURATION -> KafkaTopics.NOTIFICATION_CONFIGURATION;
            case GROUP_DATASOURCE_MIRRORING -> KafkaTopics.NOTIFICATION_DATASOURCE_MIRRORING;
            case GROUP_FILE_SYSTEM -> KafkaTopics.NOTIFICATION_FILE_SYSTEM;
            case GROUP_INTEGRATION -> KafkaTopics.NOTIFICATION_INTEGRATION;
            case GROUP_NEW_VULNERABILITY -> KafkaTopics.NOTIFICATION_NEW_VULNERABILITY;
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> KafkaTopics.NOTIFICATION_NEW_VULNERABLE_DEPENDENCY;
            case GROUP_POLICY_VIOLATION -> KafkaTopics.NOTIFICATION_POLICY_VIOLATION;
            case GROUP_PROJECT_AUDIT_CHANGE -> KafkaTopics.NOTIFICATION_PROJECT_AUDIT_CHANGE;
            case GROUP_PROJECT_CREATED -> KafkaTopics.NOTIFICATION_PROJECT_CREATED;
            case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE;
            case GROUP_REPOSITORY -> KafkaTopics.NOTIFICATION_REPOSITORY;
            case GROUP_VEX_CONSUMED, GROUP_VEX_PROCESSED -> KafkaTopics.NOTIFICATION_VEX;
            case GROUP_USER_CREATED, GROUP_USER_DELETED -> KafkaTopics.NOTIFICATION_USER;
            case GROUP_UNSPECIFIED, UNRECOGNIZED -> throw new IllegalArgumentException("""
                    Unable to determine destination topic because the notification does not \
                    specify a notification group: %s""".formatted(notification.getGroup()));
            // NB: The lack of a default case is intentional. This way, the compiler will fail
            // the build when new groups are added, and we don't have a case for it :)
        };
    }

    private static String extractEventKey(final Notification notification) throws InvalidProtocolBufferException {
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
