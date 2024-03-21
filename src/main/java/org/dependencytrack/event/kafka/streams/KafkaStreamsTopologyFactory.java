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
package org.dependencytrack.event.kafka.streams;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.ChainableEvent;
import alpine.event.framework.Event;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.KeyValue;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.Named;
import org.apache.kafka.streams.kstream.Produced;
import org.apache.kafka.streams.kstream.Repartitioned;
import org.datanucleus.PropertyNames;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.PortfolioVulnerabilityAnalysisEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.streams.processor.DelayedBomProcessedNotificationProcessor;
import org.dependencytrack.event.kafka.streams.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.streams.processor.VulnerabilityScanResultProcessor;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;
import org.dependencytrack.proto.vulnanalysis.v1.ScanResult;

import java.time.Instant;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import static org.dependencytrack.parser.dependencytrack.NotificationModelConverter.convert;
import static org.dependencytrack.util.NotificationUtil.createProjectVulnerabilityAnalysisCompleteNotification;

class KafkaStreamsTopologyFactory {

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsTopologyFactory.class);

    private final boolean delayBomProcessedNotification;

    public KafkaStreamsTopologyFactory() {
        this(Config.getInstance().getPropertyAsBoolean(ConfigKey.TMP_DELAY_BOM_PROCESSED_NOTIFICATION));
    }

    KafkaStreamsTopologyFactory(final boolean delayBomProcessedNotification) {
        this.delayBomProcessedNotification = delayBomProcessedNotification;
    }

    Topology createTopology() {
        final var streamsBuilder = new StreamsBuilder();

        final var streamsProperties = new Properties();
        streamsProperties.put(StreamsConfig.TOPOLOGY_OPTIMIZATION_CONFIG, StreamsConfig.OPTIMIZE);

        final KStream<ScanKey, ScanResult> vulnScanResultStream = streamsBuilder
                .stream(KafkaTopics.VULN_ANALYSIS_RESULT.name(), Consumed
                        .with(KafkaTopics.VULN_ANALYSIS_RESULT.keySerde(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("consume_from_%s_topic".formatted(KafkaTopics.VULN_ANALYSIS_RESULT.name())));

        // Process the vulnerabilities reported by the scanners.
        final KStream<ScanKey, ScanResult> processedVulnScanResultStream = vulnScanResultStream
                .processValues(VulnerabilityScanResultProcessor::new, Named.as("process_vuln_scan_result"));

        // Re-key processed results to their respective scan token, and record their arrival.
        final KStream<String, VulnerabilityScan> completedVulnScanStream = processedVulnScanResultStream
                // Vulnerability scans targeting the entire portfolio are currently not tracked.
                // There's no point in including results in the following repartition, and querying
                // the database for their scan token, given the queries will never return anything anyway.
                // Filtering results of portfolio analyses here also reduces the chance of hot partitions.
                .filter((scanKey, scanResult) -> !scanKey.getScanToken().equals(PortfolioVulnerabilityAnalysisEvent.CHAIN_IDENTIFIER.toString()),
                        Named.as("filter_out_portfolio_vuln_scan_results"))
                .map((scanKey, scanResult) -> {
                    // Drop vulnerabilities from scanner results, as they can be rather large, and we don't need them anymore.
                    // Dropping them will save us some compression and network overhead during the repartition.
                    // We can remove this step should we ever need access to the vulnerabilities again.
                    final var strippedScanResult = scanResult.toBuilder()
                            .clearScannerResults()
                            .addAllScannerResults(scanResult.getScannerResultsList().stream()
                                    .map(scannerResult -> scannerResult.toBuilder()
                                            .clearBom()
                                            .build())
                                    .toList())
                            .build();
                    return KeyValue.pair(scanKey.getScanToken(), strippedScanResult);
                }, Named.as("re-key_scan-result_to_scan-token"))
                .repartition(Repartitioned
                        .with(Serdes.String(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("processed-vuln-scan-result-by-scan-token"))
                .mapValues((scanToken, scanResult) -> {
                    try (final var qm = new QueryManager()) {
                        return qm.recordVulnerabilityScanResult(scanToken, scanResult);
                    }
                }, Named.as("record_processed_vuln_scan_result"))
                .filter((scanToken, vulnScan) -> vulnScan != null,
                        Named.as("filter_completed_vuln_scans"))
                .mapValues((scanToken, vulnScan) -> {
                    final double failureRate = (double) vulnScan.getScanFailed() / vulnScan.getScanTotal();

                    if (failureRate > vulnScan.getFailureThreshold()) {
                        try (var qm = new QueryManager()) {
                            // Detach VulnerabilityScan objects when committing changes. Without this,
                            // all fields except the ID field will be unloaded on commit (the object will become HOLLOW).
                            qm.getPersistenceManager().setProperty(PropertyNames.PROPERTY_DETACH_ALL_ON_COMMIT, "true");
                            vulnScan = qm.updateVulnerabilityScanStatus(vulnScan.getToken(), VulnerabilityScan.Status.FAILED);
                            vulnScan.setFailureReason("Failure threshold of " + vulnScan.getFailureThreshold() + "% exceeded: " + failureRate + "% of scans failed");
                            LOGGER.warn("Detected failure of vulnerability scan (token=%s, targetType=%s, targetIdentifier=%s): %s"
                                    .formatted(vulnScan.getToken(), vulnScan.getTargetType(), vulnScan.getTargetIdentifier(), vulnScan.getFailureReason()));
                        }
                    }

                    return vulnScan;
                }, Named.as("evaluate_vuln_scan_failure_rate"));

        completedVulnScanStream
                .foreach((scanToken, vulnScan) -> {
                    try (var qm = new QueryManager()) {
                        final WorkflowState vulnAnalysisState = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scanToken), WorkflowStep.VULN_ANALYSIS);
                        if (vulnAnalysisState == null) {
                            // No workflow exists for this scan; Nothing to update.
                            return;
                        }

                        if (vulnScan.getStatus() == VulnerabilityScan.Status.FAILED) {
                            vulnAnalysisState.setStatus(WorkflowStatus.FAILED);
                            vulnAnalysisState.setUpdatedAt(new Date());
                            vulnAnalysisState.setFailureReason(vulnScan.getFailureReason());
                            final WorkflowState updatedVulnAnalysisState = qm.updateWorkflowState(vulnAnalysisState);
                            qm.updateAllDescendantStatesOfParent(updatedVulnAnalysisState, WorkflowStatus.CANCELLED, Date.from(Instant.now()));
                            return;
                        }

                        vulnAnalysisState.setStatus(WorkflowStatus.COMPLETED);
                        vulnAnalysisState.setUpdatedAt(Date.from(Instant.now()));
                        qm.updateWorkflowState(vulnAnalysisState);
                    }
                }, Named.as("update_vuln_analysis_workflow_status"));

        final KStream<String, VulnerabilityScan> completedVulnScanWithProjectTargetStream = completedVulnScanStream
                .filter((scanToken, vulnScan) -> vulnScan.getTargetType() == VulnerabilityScan.TargetType.PROJECT,
                        Named.as("filter_vuln_scans_with_project_target"));

        // For each completed vulnerability scan that targeted a project (opposed to individual components),
        // determine its overall status, gather all findings, and emit a PROJECT_VULN_ANALYSIS_COMPLETE notification.
        completedVulnScanWithProjectTargetStream
                .map((scanToken, vulnScan) -> {
                    final alpine.notification.Notification alpineNotification;
                    try {
                        alpineNotification = vulnScan.getStatus() == VulnerabilityScan.Status.FAILED
                                ? createProjectVulnerabilityAnalysisCompleteNotification(vulnScan,
                                UUID.fromString(scanToken),
                                ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_FAILED)
                                : createProjectVulnerabilityAnalysisCompleteNotification(
                                vulnScan,
                                UUID.fromString(scanToken),
                                ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED);
                    } catch (RuntimeException e) {
                        LOGGER.warn("Failed to generate a %s notification (project: %s; token: %s)"
                                .formatted(NotificationGroup.PROJECT_VULN_ANALYSIS_COMPLETE,
                                        vulnScan.getTargetIdentifier(), vulnScan.getToken()), e);
                        return KeyValue.pair(vulnScan.getTargetIdentifier().toString(), null);
                    }

                    return KeyValue.pair(vulnScan.getTargetIdentifier().toString(), convert(alpineNotification));
                }, Named.as("map_vuln_scan_to_vuln_analysis_complete_notification"))
                .filter((projectUuid, notification) -> notification != null,
                        Named.as("filter_valid_project-vuln-analysis-complete_notification"))
                .to(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), Produced
                        .with(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.keySerde(),
                                KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.valueSerde())
                        .withName("produce_to_%s_topic".formatted(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name())));

        // When delaying of BOM_PROCESSED notifications is enabled, emit a BOM_PROCESSED notification
        // for each completed vulnerability scan that targeted a project. But only do so when the scan is
        // part of a workflow that includes a BOM_PROCESSING step with status COMPLETED.
        if (delayBomProcessedNotification) {
            completedVulnScanStream
                    .process(DelayedBomProcessedNotificationProcessor::new,
                            Named.as("tmp_delay_bom_processed_notification_process_completed_vuln_scan"))
                    .to(KafkaTopics.NOTIFICATION_BOM.name(), Produced
                            .with(KafkaTopics.NOTIFICATION_BOM.keySerde(), KafkaTopics.NOTIFICATION_BOM.valueSerde())
                            .withName("tmp_delay_bom_processed_notification_produce_to_%s_topic".formatted(KafkaTopics.NOTIFICATION_BOM.name())));
        }

        // For each successfully completed vulnerability scan, trigger a policy evaluation and metrics update
        // for the targeted entity (project or individual component).
        completedVulnScanStream
                .filter((scanToken, vulnScan) -> vulnScan.getStatus() != VulnerabilityScan.Status.FAILED,
                        Named.as("filter_failed_vuln_scans"))
                .foreach((scanToken, vulnScan) -> {
                    final ChainableEvent policyEvaluationEvent = switch (vulnScan.getTargetType()) {
                        case COMPONENT -> new ComponentPolicyEvaluationEvent(vulnScan.getTargetIdentifier());
                        case PROJECT -> new ProjectPolicyEvaluationEvent(vulnScan.getTargetIdentifier());
                    };
                    policyEvaluationEvent.setChainIdentifier(UUID.fromString(vulnScan.getToken()));

                    // Trigger a metrics update no matter if the policy evaluation succeeded or not.
                    final ChainableEvent metricsUpdateEvent = switch (vulnScan.getTargetType()) {
                        case COMPONENT -> new ComponentMetricsUpdateEvent(vulnScan.getTargetIdentifier());
                        case PROJECT -> new ProjectMetricsUpdateEvent(vulnScan.getTargetIdentifier());
                    };
                    metricsUpdateEvent.setChainIdentifier(UUID.fromString(vulnScan.getToken()));

                    policyEvaluationEvent.onFailure(metricsUpdateEvent);
                    policyEvaluationEvent.onSuccess(metricsUpdateEvent);

                    Event.dispatch(policyEvaluationEvent);
                }, Named.as("trigger_policy_evaluation"));

        streamsBuilder
                .stream(KafkaTopics.REPO_META_ANALYSIS_RESULT.name(),
                        Consumed.with(KafkaTopics.REPO_META_ANALYSIS_RESULT.keySerde(), KafkaTopics.REPO_META_ANALYSIS_RESULT.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.REPO_META_ANALYSIS_RESULT.name())))
                .process(RepositoryMetaResultProcessor::new, Named.as("process_repo_meta_analysis_result"));

        return streamsBuilder.build(streamsProperties);
    }

}
