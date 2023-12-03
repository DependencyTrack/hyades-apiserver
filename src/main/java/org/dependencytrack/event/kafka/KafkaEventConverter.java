package org.dependencytrack.event.kafka;

import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;
import org.dependencytrack.parser.dependencytrack.NotificationModelConverter;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisCommand;
import org.dependencytrack.proto.vulnanalysis.v1.ScanCommand;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Utility class to convert {@link alpine.event.framework.Event}s and {@link alpine.notification.Notification}s
 * to {@link KafkaEvent}s.
 */
final class KafkaEventConverter {

    private KafkaEventConverter() {
    }

    static KafkaEvent<ScanKey, ScanCommand> convert(final ComponentVulnerabilityAnalysisEvent event) {
        final var componentBuilder = org.dependencytrack.proto.vulnanalysis.v1.Component.newBuilder()
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
        Optional.ofNullable(event.componentUuid()).map(uuid -> uuid.toString()).ifPresent(componentBuilder::setUuid);

        final var analysisCommand = AnalysisCommand.newBuilder()
                .setComponent(componentBuilder)
                .setFetchMeta(event.fetchMeta())
                .build();

        return new KafkaEvent<>(KafkaTopics.REPO_META_ANALYSIS_COMMAND, event.purlCoordinates(), analysisCommand, null);
    }

    static KafkaEvent<String, Notification> convert(final String key, final Notification notification) {
        final Topic<String, Notification> topic = switch (notification.getGroup()) {
            case GROUP_CONFIGURATION -> KafkaTopics.NOTIFICATION_CONFIGURATION;
            case GROUP_DATASOURCE_MIRRORING -> KafkaTopics.NOTIFICATION_DATASOURCE_MIRRORING;
            case GROUP_REPOSITORY -> KafkaTopics.NOTIFICATION_REPOSITORY;
            case GROUP_INTEGRATION -> KafkaTopics.NOTIFICATION_INTEGRATION;
            case GROUP_ANALYZER -> KafkaTopics.NOTIFICATION_ANALYZER;
            case GROUP_BOM_CONSUMED -> KafkaTopics.NOTIFICATION_BOM;
            case GROUP_BOM_PROCESSED -> KafkaTopics.NOTIFICATION_BOM;
            case GROUP_FILE_SYSTEM -> KafkaTopics.NOTIFICATION_FILE_SYSTEM;
            case GROUP_NEW_VULNERABILITY -> KafkaTopics.NOTIFICATION_NEW_VULNERABILITY;
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> KafkaTopics.NOTIFICATION_NEW_VULNERABLE_DEPENDENCY;
            case GROUP_POLICY_VIOLATION -> KafkaTopics.NOTIFICATION_POLICY_VIOLATION;
            case GROUP_PROJECT_AUDIT_CHANGE -> KafkaTopics.NOTIFICATION_PROJECT_AUDIT_CHANGE;
            case GROUP_PROJECT_CREATED -> KafkaTopics.NOTIFICATION_PROJECT_CREATED;
            case GROUP_VEX_CONSUMED -> KafkaTopics.NOTIFICATION_VEX;
            case GROUP_VEX_PROCESSED -> KafkaTopics.NOTIFICATION_VEX;
            case GROUP_BOM_PROCESSING_FAILED -> KafkaTopics.NOTIFICATION_BOM;
            case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE;
            default -> null;
        };
        if (topic == null) {
            return null;
        }

        return new KafkaEvent<>(topic, key, notification, null);
    }

    static KafkaEvent<String, Notification> convert(final UUID projectUuid, final alpine.notification.Notification alpineNotification) {
        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        return convert(projectUuid != null ? projectUuid.toString() : null, notification);
    }

}
