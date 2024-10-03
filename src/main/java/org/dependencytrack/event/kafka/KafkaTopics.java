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

import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serdes;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerde;
import org.dependencytrack.proto.mirror.v1.EpssItem;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisCommand;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.proto.vulnanalysis.v1.ScanCommand;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;
import org.dependencytrack.proto.vulnanalysis.v1.ScanResult;
import org.dependencytrack.proto.vulnanalysis.v1.ScannerResult;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.apache.kafka.common.config.TopicConfig.CLEANUP_POLICY_COMPACT;
import static org.apache.kafka.common.config.TopicConfig.CLEANUP_POLICY_CONFIG;
import static org.apache.kafka.common.config.TopicConfig.RETENTION_MS_CONFIG;

public final class KafkaTopics {

    public record Topic<K, V>(
            String name,
            Serde<K> keySerde,
            Serde<V> valueSerde,
            Config defaultConfig) {

        /**
         * @since 5.6.0
         */
        public record Config(
                int partitions,
                short replicationFactor,
                Map<String, String> configs) {
        }

        @Override
        public String name() {
            return alpine.Config.getInstance().getProperty(ConfigKey.DT_KAFKA_TOPIC_PREFIX) + name;
        }

    }

    public static final Topic<String, EpssItem> TOPIC_EPSS;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_ANALYZER;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_BOM;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_CONFIGURATION;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_DATASOURCE_MIRRORING;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_FILE_SYSTEM;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_INTEGRATION;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_NEW_VULNERABILITY;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_NEW_VULNERABLE_DEPENDENCY;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_POLICY_VIOLATION;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_PROJECT_AUDIT_CHANGE;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_PROJECT_CREATED;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_REPOSITORY;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_VEX;
    public static final Topic<String, Notification> TOPIC_NOTIFICATION_USER;
    public static final Topic<String, AnalysisCommand> TOPIC_REPO_META_ANALYSIS_COMMAND;
    public static final Topic<String, AnalysisResult> TOPIC_REPO_META_ANALYSIS_RESULT;
    public static final Topic<ScanKey, ScanCommand> TOPIC_VULN_ANALYSIS_COMMAND;
    public static final Topic<ScanKey, ScanResult> TOPIC_VULN_ANALYSIS_RESULT;
    public static final Topic<String, ScanResult> TOPIC_VULN_ANALYSIS_RESULT_PROCESSED;
    public static final Topic<ScanKey, ScannerResult> TOPIC_VULN_ANALYSIS_SCANNER_RESULT;
    public static final Topic<String, Bom> TOPIC_VULNERABILITY;
    public static final Topic<String, String> TOPIC_VULNERABILITY_MIRROR_COMMAND;
    public static final List<Topic<?, ?>> ALL_TOPICS;

    private static final String DEFAULT_RETENTION_MS = String.valueOf(TimeUnit.HOURS.toMillis(12));
    private static final Serde<Notification> NOTIFICATION_PROTO_SERDE = new KafkaProtobufSerde<>(Notification.parser());


    static {
        // TODO: Provide a way to (partially) overwrite the default configs.

        TOPIC_EPSS = new Topic<>(
                "dtrack.epss",
                Serdes.String(),
                new KafkaProtobufSerde<>(EpssItem.parser()),
                new Topic.Config(3, (short) 1, Map.of(CLEANUP_POLICY_CONFIG, CLEANUP_POLICY_COMPACT)));
        TOPIC_NOTIFICATION_ANALYZER = new Topic<>(
                "dtrack.notification.analyzer",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_BOM = new Topic<>(
                "dtrack.notification.bom",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_CONFIGURATION = new Topic<>(
                "dtrack.notification.configuration",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_DATASOURCE_MIRRORING = new Topic<>(
                "dtrack.notification.datasource-mirroring",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_FILE_SYSTEM = new Topic<>(
                "dtrack.notification.file-system",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_INTEGRATION = new Topic<>(
                "dtrack.notification.integration",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_NEW_VULNERABILITY = new Topic<>(
                "dtrack.notification.new-vulnerability",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_NEW_VULNERABLE_DEPENDENCY = new Topic<>(
                "dtrack.notification.new-vulnerable-dependency",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_POLICY_VIOLATION = new Topic<>(
                "dtrack.notification.policy-violation",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_PROJECT_AUDIT_CHANGE = new Topic<>(
                "dtrack.notification.project-audit-change",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_PROJECT_CREATED = new Topic<>(
                "dtrack.notification.project-created",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE = new Topic<>(
                "dtrack.notification.project-vuln-analysis-complete",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_REPOSITORY = new Topic<>(
                "dtrack.notification.repository",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_USER = new Topic<>(
                "dtrack.notification.user",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_NOTIFICATION_VEX = new Topic<>(
                "dtrack.notification.vex",
                Serdes.String(),
                NOTIFICATION_PROTO_SERDE,
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_REPO_META_ANALYSIS_COMMAND = new Topic<>(
                "dtrack.repo-meta-analysis.component",
                Serdes.String(),
                new KafkaProtobufSerde<>(AnalysisCommand.parser()),
                new Topic.Config(3, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_REPO_META_ANALYSIS_RESULT = new Topic<>(
                "dtrack.repo-meta-analysis.result",
                Serdes.String(),
                new KafkaProtobufSerde<>(AnalysisResult.parser()),
                new Topic.Config(3, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_VULN_ANALYSIS_COMMAND = new Topic<>(
                "dtrack.vuln-analysis.component",
                new KafkaProtobufSerde<>(ScanKey.parser()),
                new KafkaProtobufSerde<>(ScanCommand.parser()),
                new Topic.Config(3, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_VULN_ANALYSIS_RESULT = new Topic<>(
                "dtrack.vuln-analysis.result",
                new KafkaProtobufSerde<>(ScanKey.parser()),
                new KafkaProtobufSerde<>(ScanResult.parser()),
                new Topic.Config(3, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_VULN_ANALYSIS_RESULT_PROCESSED = new Topic<>(
                "dtrack.vuln-analysis.result.processed",
                Serdes.String(),
                new KafkaProtobufSerde<>(ScanResult.parser()),
                new Topic.Config(3, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_VULN_ANALYSIS_SCANNER_RESULT = new Topic<>(
                "dtrack.vuln-analysis.scanner.result",
                new KafkaProtobufSerde<>(ScanKey.parser()),
                new KafkaProtobufSerde<>(ScannerResult.parser()),
                new Topic.Config(3, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));
        TOPIC_VULNERABILITY = new Topic<>(
                "dtrack.vulnerability",
                Serdes.String(),
                new KafkaProtobufSerde<>(Bom.parser()),
                new Topic.Config(1, (short) 1, Map.of(CLEANUP_POLICY_CONFIG, CLEANUP_POLICY_COMPACT)));
        TOPIC_VULNERABILITY_MIRROR_COMMAND = new Topic<>(
                "dtrack.vulnerability.mirror.command",
                Serdes.String(),
                Serdes.String(),
                new Topic.Config(1, (short) 1, Map.of(RETENTION_MS_CONFIG, DEFAULT_RETENTION_MS)));

        ALL_TOPICS = List.of(
                TOPIC_EPSS,
                TOPIC_NOTIFICATION_ANALYZER,
                TOPIC_NOTIFICATION_BOM,
                TOPIC_NOTIFICATION_CONFIGURATION,
                TOPIC_NOTIFICATION_DATASOURCE_MIRRORING,
                TOPIC_NOTIFICATION_FILE_SYSTEM,
                TOPIC_NOTIFICATION_INTEGRATION,
                TOPIC_NOTIFICATION_NEW_VULNERABILITY,
                TOPIC_NOTIFICATION_NEW_VULNERABLE_DEPENDENCY,
                TOPIC_NOTIFICATION_POLICY_VIOLATION,
                TOPIC_NOTIFICATION_PROJECT_AUDIT_CHANGE,
                TOPIC_NOTIFICATION_PROJECT_CREATED,
                TOPIC_NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE,
                TOPIC_NOTIFICATION_REPOSITORY,
                TOPIC_NOTIFICATION_VEX,
                TOPIC_NOTIFICATION_USER,
                TOPIC_REPO_META_ANALYSIS_COMMAND,
                TOPIC_REPO_META_ANALYSIS_RESULT,
                TOPIC_VULN_ANALYSIS_COMMAND,
                TOPIC_VULN_ANALYSIS_RESULT,
                TOPIC_VULN_ANALYSIS_RESULT_PROCESSED,
                TOPIC_VULN_ANALYSIS_SCANNER_RESULT,
                TOPIC_VULNERABILITY,
                TOPIC_VULNERABILITY_MIRROR_COMMAND);
    }

}
