package org.dependencytrack.event.kafka;

import alpine.event.framework.ChainableEvent;
import alpine.event.framework.Event;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.Named;
import org.apache.kafka.streams.kstream.Repartitioned;
import org.datanucleus.PropertyNames;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.kafka.processor.MirrorVulnerabilityProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityScanResultProcessor;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;

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
        // Re-key the result stream to component UUIDs to ensure that results
        // for the same component are processed in a serial fashion.
        //
        // Results with status COMPLETE are re-keyed back to scan keys
        // and forwarded, all other results are dropped after successful processing.
        final KStream<UUID, ScanResult> processedVulnScanResultStream = vulnScanResultStream
                .selectKey((scanKey, scanResult) -> UUID.fromString(scanKey.getComponentUuid()),
                        Named.as("re-key_vuln_scan_result_to_component_uuid"))
                .repartition(Repartitioned
                        .with(Serdes.UUID(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("vuln-scan-result-by-component-uuid"))
                .processValues(VulnerabilityScanResultProcessor::new, Named.as("process_vuln_scan_result"));

        // Re-key processed results to their respective scan token, and record their arrival.
        final KStream<String, VulnerabilityScan> completedVulnScanStream = processedVulnScanResultStream
                .selectKey((componentUuid, scanResult) -> scanResult.getKey().getScanToken())
                .repartition(Repartitioned
                        .with(Serdes.String(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("processed-vuln-scan-result-by-scan-token"))
                .mapValues((scanToken, scanResult) -> {
                    try (final var qm = new QueryManager()) {
                        qm.getPersistenceManager().setProperty(PropertyNames.PROPERTY_CACHE_L2_TYPE, "none");
                        // Detach VulnerabilityScan objects when committing changes. Without this,
                        // all fields except the ID field will be unloaded on commit (the object will become HOLLOW),
                        // causing the call to getStatus() to trigger a database query behind the scenes.
                        qm.getPersistenceManager().setProperty(PropertyNames.PROPERTY_DETACH_ALL_ON_COMMIT, "true");

                        final VulnerabilityScan vulnScan = qm.recordVulnerabilityScanResult(scanToken);
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

        completedVulnScanStream
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
