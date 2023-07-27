package org.dependencytrack.event.kafka;

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
import org.dependencytrack.event.kafka.processor.MirrorVulnerabilityProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityScanResultProcessor;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.parser.hyades.NotificationModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;

import java.time.Instant;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

class KafkaStreamsTopologyFactory {

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
                    // Drop scanner results, as they can be rather large, and we don't need them anymore.
                    // Dropping them will save us some compression and network overhead during the repartition.
                    // We can remove this step should we ever need access to the results again.
                    scanResult.getScannerResultsList().stream().forEach(scannerResult -> scannerResult.toBuilder().clearBom().build());
                    return KeyValue.pair(scanKey.getScanToken(), scanResult);
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
                        Named.as("filter_completed_vuln_scans"));

        completedVulnScanStream.filter((scantoken, vulnscan) -> vulnscan.getTargetType() == VulnerabilityScan.TargetType.PROJECT,
                        Named.as("filter_vuln_scans_with_project_target"))
                .map((scantoken, vulnscan) -> {
                    // check the failure rate and update workflow status accordingly.
                    final double failureRate = (double) vulnscan.getScanFailed() / vulnscan.getScanTotal();
                    try (var qm = new QueryManager()) {
                        if (failureRate > vulnscan.getFailureThreshold()) {
                            var vulnAnalysisState = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scantoken), WorkflowStep.VULN_ANALYSIS);
                            vulnAnalysisState.setStatus(WorkflowStatus.FAILED);
                            vulnAnalysisState.setUpdatedAt(Date.from(Instant.now()));
                            WorkflowState updatedState = qm.updateWorkflowState(vulnAnalysisState);
                            qm.updateAllDescendantStatesOfParent(updatedState, WorkflowStatus.CANCELLED, Date.from(Instant.now()));
                            vulnscan.setStatus(VulnerabilityScan.Status.FAILED);
                            qm.persist(vulnscan);
                            return KeyValue.pair(vulnscan.getTargetIdentifier().toString(), null);
                        } else {
                            var vulnAnalysisState = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scantoken), WorkflowStep.VULN_ANALYSIS);
                            vulnAnalysisState.setStatus(WorkflowStatus.COMPLETED);
                            vulnAnalysisState.setUpdatedAt(Date.from(Instant.now()));
                            qm.updateWorkflowState(vulnAnalysisState);
                            var notification = NotificationModelConverter.convert(NotificationUtil.createProjectVulnerabilityAnalysisCompleteNotification(vulnscan));
                            return KeyValue.pair(vulnscan.getTargetIdentifier().toString(), notification);
                        }
                    }
                }).filter((scantoken, notification) -> notification != null,
                        Named.as("filter_vuln_scans_with_notification"))
                .to(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(),
                        Produced.with(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.keySerde(),
                                KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.valueSerde()));

        completedVulnScanStream
                .filter((scanToken, vulnScan) -> vulnScan.getStatus() != VulnerabilityScan.Status.FAILED)
                .foreach((scanToken, vulnScan) -> {
                    final ChainableEvent policyEvaluationEvent = switch (vulnScan.getTargetType()) {
                        case COMPONENT -> new ComponentPolicyEvaluationEvent(vulnScan.getTargetIdentifier());
                        case PROJECT -> new ProjectPolicyEvaluationEvent(vulnScan.getTargetIdentifier());
                    };
                    policyEvaluationEvent.setChainIdentifier(UUID.fromString(vulnScan.getToken()));

                    // Trigger a metrics update no matter if the policy evaluation succeeded or not.
                    final Event metricsUpdateEvent = switch (vulnScan.getTargetType()) {
                        case COMPONENT -> new ComponentMetricsUpdateEvent(vulnScan.getTargetIdentifier());
                        case PROJECT -> new ProjectMetricsUpdateEvent(vulnScan.getTargetIdentifier());
                    };
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
                .stream(KafkaTopics.NEW_VULNERABILITY.name(),
                        Consumed.with(KafkaTopics.NEW_VULNERABILITY.keySerde(), KafkaTopics.NEW_VULNERABILITY.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.NEW_VULNERABILITY.name())))
                .process(MirrorVulnerabilityProcessor::new, Named.as("process_mirror_vulnerability"));

        return streamsBuilder.build(streamsProperties);
    }

}
