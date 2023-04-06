package org.dependencytrack.event.kafka;

import com.github.packageurl.PackageURL;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;
import org.dependencytrack.parser.hyades.NotificationModelConverter;
import org.hyades.proto.notification.v1.Notification;
import org.hyades.proto.repometaanalysis.v1.AnalysisCommand;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;

import java.util.Map;
import java.util.Optional;

/**
 * Utility class to convert {@link alpine.event.framework.Event}s and {@link alpine.notification.Notification}s
 * to {@link KafkaEvent}s.
 */
final class KafkaEventConverter {

    private KafkaEventConverter() {
    }

    static KafkaEvent<ScanKey, ScanCommand> convert(final ComponentVulnerabilityAnalysisEvent event) {
        final var componentBuilder = org.hyades.proto.vulnanalysis.v1.Component.newBuilder()
                .setUuid(event.component().getUuid().toString())
                .setInternal(event.component().isInternal());
        Optional.ofNullable(event.component().getCpe()).ifPresent(componentBuilder::setCpe);
        Optional.ofNullable(event.component().getPurl()).map(PackageURL::canonicalize).ifPresent(componentBuilder::setPurl);
        Optional.ofNullable(event.component().getSwidTagId()).ifPresent(componentBuilder::setSwidTagId);

        final var scanKey = ScanKey.newBuilder()
                .setScanToken(event.token().toString())
                .setComponentUuid(event.component().getUuid().toString())
                .build();

        final var scanCommand = ScanCommand.newBuilder()
                .setComponent(componentBuilder)
                .build();

        return new KafkaEvent<>(
                KafkaTopics.VULN_ANALYSIS_COMMAND,
                scanKey, scanCommand,
                Map.of(KafkaEventHeaders.VULN_ANALYSIS_LEVEL, event.level().name())
        );
    }

    static KafkaEvent<String, AnalysisCommand> convert(final ComponentRepositoryMetaAnalysisEvent event) {
        if (event.component() == null || event.component().getPurl() == null) {
            return null;
        }

        final String purl = event.component().getPurl().canonicalize();
        final var analysisCommand = AnalysisCommand.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl(event.component().getPurl().canonicalize())
                        .setInternal(event.component().isInternal()))
                .build();

        return new KafkaEvent<>(KafkaTopics.REPO_META_ANALYSIS_COMMAND, purl, analysisCommand, null);
    }

    static KafkaEvent<String, Notification> convert(final alpine.notification.Notification alpineNotification) {
        final Notification notification = NotificationModelConverter.convert(alpineNotification);

        final Topic<String, Notification> topic = switch (notification.getGroup()) {
            case GROUP_CONFIGURATION -> KafkaTopics.NOTIFICATION_CONFIGURATION;
            case GROUP_DATASOURCE_MIRRORING -> KafkaTopics.NOTIFICATION_DATASOURCE_MIRRORING;
            case GROUP_REPOSITORY -> KafkaTopics.NOTIFICATION_REPOSITORY;
            case GROUP_INTEGRATION -> KafkaTopics.NOTIFICATION_INTEGRATION;
            case GROUP_ANALYZER -> KafkaTopics.NOTIFICATION_ANALYZER;
            case GROUP_BOM_CONSUMED -> KafkaTopics.NOTIFICATION_BOM_CONSUMED;
            case GROUP_BOM_PROCESSED -> KafkaTopics.NOTIFICATION_BOM_PROCESSED;
            case GROUP_FILE_SYSTEM -> KafkaTopics.NOTIFICATION_FILE_SYSTEM;
            case GROUP_INDEXING_SERVICE -> KafkaTopics.NOTIFICATION_INDEXING_SERVICE;
            case GROUP_NEW_VULNERABILITY -> KafkaTopics.NOTIFICATION_NEW_VULNERABILITY;
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> KafkaTopics.NOTIFICATION_NEW_VULNERABLE_DEPENDENCY;
            case GROUP_POLICY_VIOLATION -> KafkaTopics.NOTIFICATION_POLICY_VIOLATION;
            case GROUP_PROJECT_AUDIT_CHANGE -> KafkaTopics.NOTIFICATION_PROJECT_AUDIT_CHANGE;
            case GROUP_PROJECT_CREATED -> KafkaTopics.NOTIFICATION_PROJECT_CREATED;
            case GROUP_VEX_CONSUMED -> KafkaTopics.NOTIFICATION_VEX_CONSUMED;
            case GROUP_VEX_PROCESSED -> KafkaTopics.NOTIFICATION_VEX_PROCESSED;
            case GROUP_BOM_PROCESSING_FAILED -> KafkaTopics.NOTIFICATION_BOM_PROCESSING_FAILED;
            default -> null;
        };
        if (topic == null) {
            return null;
        }

        return new KafkaEvent<>(topic, null, notification, null);
    }

}
