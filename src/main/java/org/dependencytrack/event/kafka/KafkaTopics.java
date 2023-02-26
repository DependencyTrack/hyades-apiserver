package org.dependencytrack.event.kafka;

import alpine.notification.Notification;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serdes;
import org.cyclonedx.model.Bom;
import org.dependencytrack.event.kafka.dto.Component;
import org.dependencytrack.event.kafka.serialization.JacksonSerde;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerde;
import org.dependencytrack.model.MetaModel;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;

import java.util.UUID;

public final class KafkaTopics {

    public static final Topic<String, Notification> NOTIFICATION_ANALYZER;
    public static final Topic<String, Notification> NOTIFICATION_BOM_CONSUMED;
    public static final Topic<String, Notification> NOTIFICATION_BOM_PROCESSED;
    public static final Topic<String, Notification> NOTIFICATION_CONFIGURATION;
    public static final Topic<String, Notification> NOTIFICATION_DATASOURCE_MIRRORING;
    public static final Topic<String, Notification> NOTIFICATION_FILE_SYSTEM;
    public static final Topic<String, Notification> NOTIFICATION_INDEXING_SERVICE;
    public static final Topic<String, Notification> NOTIFICATION_INTEGRATION;
    public static final Topic<String, Notification> NOTIFICATION_NEW_VULNERABILITY;
    public static final Topic<String, Notification> NOTIFICATION_NEW_VULNERABLE_DEPENDENCY;
    public static final Topic<String, Notification> NOTIFICATION_POLICY_VIOLATION;
    public static final Topic<String, Notification> NOTIFICATION_PROJECT_AUDIT_CHANGE;
    public static final Topic<String, Notification> NOTIFICATION_PROJECT_CREATED;
    public static final Topic<String, Notification> NOTIFICATION_REPOSITORY;
    public static final Topic<String, Notification> NOTIFICATION_VEX_CONSUMED;
    public static final Topic<String, Notification> NOTIFICATION_VEX_PROCESSED;

    public static final Topic<String, String> MIRROR_NVD;
    public static final Topic<String, String> MIRROR_OSV;
    public static final Topic<String, Bom> NEW_VULNERABILITY;
    public static final Topic<String, Component> REPO_META_ANALYSIS_COMPONENT;
    public static final Topic<UUID, MetaModel> REPO_META_ANALYSIS_RESULT;
    public static final Topic<ScanKey, ScanCommand> VULN_ANALYSIS_COMMAND;
    public static final Topic<ScanKey, ScanResult> VULN_ANALYSIS_RESULT;

    static {
        NOTIFICATION_ANALYZER = new Topic<>("dtrack.notification.analyzer", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_BOM_CONSUMED = new Topic<>("dtrack.notification.bom-consumed", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_BOM_PROCESSED = new Topic<>("dtrack.notification.bom-processed", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_CONFIGURATION = new Topic<>("dtrack.notification.configuration", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_DATASOURCE_MIRRORING = new Topic<>("dtrack.notification.datasource-mirroring", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_FILE_SYSTEM = new Topic<>("dtrack.notification.file-system", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_INDEXING_SERVICE = new Topic<>("dtrack.notification.indexing-service", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_INTEGRATION = new Topic<>("dtrack.notification.integration", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_NEW_VULNERABILITY = new Topic<>("dtrack.notification.new-vulnerability", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_NEW_VULNERABLE_DEPENDENCY = new Topic<>("dtrack.notification.new-vulnerable-dependency", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_POLICY_VIOLATION = new Topic<>("dtrack.notification.policy-violation", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_PROJECT_AUDIT_CHANGE = new Topic<>("dtrack.notification.project-audit-change", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_PROJECT_CREATED = new Topic<>("dtrack.notification.project-created", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_REPOSITORY = new Topic<>("dtrack.notification.repository", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_VEX_CONSUMED = new Topic<>("dtrack.notification.vex-consumed", Serdes.String(), new JacksonSerde<>(Notification.class));
        NOTIFICATION_VEX_PROCESSED = new Topic<>("dtrack.notification.vex-processed", Serdes.String(), new JacksonSerde<>(Notification.class));

        MIRROR_NVD = new Topic<>("dtrack.vulnerability.mirror.nvd", Serdes.String(), Serdes.String());
        MIRROR_OSV = new Topic<>("dtrack.vulnerability.mirror.osv", Serdes.String(), Serdes.String());
        NEW_VULNERABILITY = new Topic<>("dtrack.vulnerability", Serdes.String(), new JacksonSerde<>(Bom.class));
        REPO_META_ANALYSIS_COMPONENT = new Topic<>("dtrack.repo-meta-analysis.component", Serdes.String(), new JacksonSerde<>(Component.class));
        REPO_META_ANALYSIS_RESULT = new Topic<>("dtrack.repo-meta-analysis.result", Serdes.UUID(), new JacksonSerde<>(MetaModel.class));
        VULN_ANALYSIS_COMMAND = new Topic<>("dtrack.vuln-analysis.component", new KafkaProtobufSerde<>(ScanKey.parser()), new KafkaProtobufSerde<>(ScanCommand.parser()));
        VULN_ANALYSIS_RESULT = new Topic<>("dtrack.vuln-analysis.result", new KafkaProtobufSerde<>(ScanKey.parser()), new KafkaProtobufSerde<>(ScanResult.parser()));
    }

    public record Topic<K, V>(String name, Serde<K> keySerde, Serde<V> valueSerde) {
    }

}
