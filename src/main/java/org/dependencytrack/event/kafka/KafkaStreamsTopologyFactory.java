package org.dependencytrack.event.kafka;

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
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.event.kafka.processor.IntegrityAnalysisResultProcessor;
import org.dependencytrack.event.kafka.processor.MirrorVulnerabilityProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityScanResultProcessor;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.notification.v1.ProjectVulnAnalysisStatus;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;

import java.time.Instant;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import static org.dependencytrack.parser.hyades.NotificationModelConverter.convert;
import static org.dependencytrack.util.NotificationUtil.createProjectVulnerabilityAnalysisCompleteNotification;

class KafkaStreamsTopologyFactory {

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsTopologyFactory.class);

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
                .mapValues((scanToken, value) -> {
                    try (final var qm = new QueryManager().withL2CacheDisabled()) {
                        // Detach VulnerabilityScan objects when committing changes. Without this,
                        // all fields except the ID field will be unloaded on commit (the object will become HOLLOW),
                        // causing the call to getStatus() to trigger a database query behind the scenes.
                        qm.getPersistenceManager().setProperty(PropertyNames.PROPERTY_DETACH_ALL_ON_COMMIT, "true");

                        final VulnerabilityScan vulnScan = qm.recordVulnerabilityScanResult(scanToken, value);
                        if (vulnScan == null || vulnScan.getStatus() != VulnerabilityScan.Status.COMPLETED) {
                            // When the vulnerability scan is not completed, we don't care about it.
                            // We'll filter out nulls in the next filter step.
                            return null;
                        }

                        return vulnScan;
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

        completedVulnScanStream
                .filter((scanToken, vulnScan) -> vulnScan.getTargetType() == VulnerabilityScan.TargetType.PROJECT,
                        Named.as("filter_vuln_scans_with_project_target"))
                .map((scanToken, vulnScan) -> {
                    final alpine.notification.Notification alpineNotification;
                    try {
                        alpineNotification = vulnScan.getStatus() == VulnerabilityScan.Status.FAILED
                                ? createProjectVulnerabilityAnalysisCompleteNotification(vulnScan,
                                ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_FAILED)
                                : createProjectVulnerabilityAnalysisCompleteNotification(
                                vulnScan, ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED);
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

        streamsBuilder
                .stream(KafkaTopics.INTEGRITY_ANALYSIS_RESULT.name(),
                        Consumed.with(KafkaTopics.INTEGRITY_ANALYSIS_RESULT.keySerde(), KafkaTopics.INTEGRITY_ANALYSIS_RESULT.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.INTEGRITY_ANALYSIS_RESULT.name())))
                .process(IntegrityAnalysisResultProcessor::new, Named.as("process_component_integrity_analysis_result"));

        streamsBuilder
                .stream(KafkaTopics.NEW_VULNERABILITY.name(),
                        Consumed.with(KafkaTopics.NEW_VULNERABILITY.keySerde(), KafkaTopics.NEW_VULNERABILITY.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.NEW_VULNERABILITY.name())))
                .process(MirrorVulnerabilityProcessor::new, Named.as("process_mirror_vulnerability"));

        return streamsBuilder.build(streamsProperties);
    }

}
