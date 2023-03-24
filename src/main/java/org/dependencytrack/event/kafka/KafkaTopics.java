package org.dependencytrack.event.kafka;

import alpine.Config;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serdes;
import org.cyclonedx.model.Bom;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.serialization.JacksonSerde;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerde;
import org.hyades.proto.notification.v1.Notification;
import org.hyades.proto.repometaanalysis.v1.AnalysisCommand;
import org.hyades.proto.repometaanalysis.v1.AnalysisResult;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;

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
    public static final Topic<String, String> VULNERABILITY_MIRROR_COMMAND;
    public static final Topic<String, Bom> NEW_VULNERABILITY;
    public static final Topic<String, AnalysisCommand> REPO_META_ANALYSIS_COMMAND;
    public static final Topic<String, AnalysisResult> REPO_META_ANALYSIS_RESULT;
    public static final Topic<ScanKey, ScanCommand> VULN_ANALYSIS_COMMAND;
    public static final Topic<ScanKey, ScanResult> VULN_ANALYSIS_RESULT;


    // As ObjectMapper construction is rather expensive, share a common instance across all JSON Serdes.
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    private static final Serde<Notification> NOTIFICATION_SERDE = new KafkaProtobufSerde<>(Notification.parser());

    static {
        NOTIFICATION_ANALYZER = new Topic<>("dtrack.notification.analyzer", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_BOM_CONSUMED = new Topic<>("dtrack.notification.bom-consumed", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_BOM_PROCESSED = new Topic<>("dtrack.notification.bom-processed", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_CONFIGURATION = new Topic<>("dtrack.notification.configuration", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_DATASOURCE_MIRRORING = new Topic<>("dtrack.notification.datasource-mirroring", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_FILE_SYSTEM = new Topic<>("dtrack.notification.file-system", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_INDEXING_SERVICE = new Topic<>("dtrack.notification.indexing-service", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_INTEGRATION = new Topic<>("dtrack.notification.integration", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_NEW_VULNERABILITY = new Topic<>("dtrack.notification.new-vulnerability", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_NEW_VULNERABLE_DEPENDENCY = new Topic<>("dtrack.notification.new-vulnerable-dependency", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_POLICY_VIOLATION = new Topic<>("dtrack.notification.policy-violation", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_PROJECT_AUDIT_CHANGE = new Topic<>("dtrack.notification.project-audit-change", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_PROJECT_CREATED = new Topic<>("dtrack.notification.project-created", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_REPOSITORY = new Topic<>("dtrack.notification.repository", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_VEX_CONSUMED = new Topic<>("dtrack.notification.vex-consumed", Serdes.String(), NOTIFICATION_SERDE);
        NOTIFICATION_VEX_PROCESSED = new Topic<>("dtrack.notification.vex-processed", Serdes.String(), NOTIFICATION_SERDE);

        MIRROR_NVD = new Topic<>("dtrack.vulnerability.mirror.nvd", Serdes.String(), Serdes.String());
        MIRROR_OSV = new Topic<>("dtrack.vulnerability.mirror.osv", Serdes.String(), Serdes.String());
        VULNERABILITY_MIRROR_COMMAND = new Topic<>("dtrack.vulnerability.mirror.command", Serdes.String(), Serdes.String());
        NEW_VULNERABILITY = new Topic<>("dtrack.vulnerability", Serdes.String(), new JacksonSerde<>(Bom.class, OBJECT_MAPPER));
        REPO_META_ANALYSIS_COMMAND = new Topic<>("dtrack.repo-meta-analysis.component", Serdes.String(), new KafkaProtobufSerde<>(AnalysisCommand.parser()));
        REPO_META_ANALYSIS_RESULT = new Topic<>("dtrack.repo-meta-analysis.result", Serdes.String(), new KafkaProtobufSerde<>(AnalysisResult.parser()));
        VULN_ANALYSIS_COMMAND = new Topic<>("dtrack.vuln-analysis.component", new KafkaProtobufSerde<>(ScanKey.parser()), new KafkaProtobufSerde<>(ScanCommand.parser()));
        VULN_ANALYSIS_RESULT = new Topic<>("dtrack.vuln-analysis.result", new KafkaProtobufSerde<>(ScanKey.parser()), new KafkaProtobufSerde<>(ScanResult.parser()));
    }

    public record Topic<K, V>(String name, Serde<K> keySerde, Serde<V> valueSerde) {

        @Override
        public String name() {
            return Config.getInstance().getProperty(ConfigKey.KAFKA_TOPIC_PREFIX) + name;
        }

    }

}
