package org.dependencytrack.event.kafka;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.Named;
import org.apache.kafka.streams.kstream.Repartitioned;
import org.datanucleus.PropertyNames;
import org.dependencytrack.event.kafka.processor.MirrorVulnerabilityProcessor;
import org.dependencytrack.event.kafka.processor.PortfolioMetricsProcessor;
import org.dependencytrack.event.kafka.processor.ProjectMetricsProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityScanResultProcessor;
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
        final KStream<UUID, ScanResult> processedVulnScanResulStream = vulnScanResultStream
                .selectKey((scanKey, scanResult) -> UUID.fromString(scanKey.getComponentUuid()),
                        Named.as("re-key_vuln_scan_result_to_component_uuid"))
                .repartition(Repartitioned
                        .with(Serdes.UUID(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("vuln-scan-result-by-component-uuid"))
                .processValues(VulnerabilityScanResultProcessor::new, Named.as("process_vuln_scan_result"));
        // TODO: Kick off policy evaluation when vulnerability analysis completed,
        // as some policies may check for things like severities etc.

        // Re-key processed results to their respective scan token, and record their arrival.
        processedVulnScanResulStream
                .selectKey((componentUuid, scanResult) -> scanResult.getKey().getScanToken())
                .repartition(Repartitioned
                        .with(Serdes.String(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("processed-vuln-scan-result-by-scan-token"))
                .foreach((scanToken, scanResult) -> {
                    try (final var qm = new QueryManager()) {
                        // Disable L2 cache, there's no need for it here
                        qm.getPersistenceManager().setProperty(PropertyNames.PROPERTY_CACHE_L2_TYPE, "none");
                        qm.recordVulnerabilityScanResult(scanToken);
                    }
                }, Named.as("record_processed_vuln_scan_result"));

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

        streamsBuilder
                .stream(KafkaTopics.PROJECT_METRICS.name(),
                        Consumed.with(KafkaTopics.PROJECT_METRICS.keySerde(), KafkaTopics.PROJECT_METRICS.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.PROJECT_METRICS.name())))
                .process(ProjectMetricsProcessor::new, Named.as("project_metrics_result"));

        streamsBuilder
                .stream(KafkaTopics.PORTFOLIO_METRICS.name(),
                        Consumed.with(KafkaTopics.PORTFOLIO_METRICS.keySerde(), KafkaTopics.PORTFOLIO_METRICS.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.PORTFOLIO_METRICS.name())))
                .process(PortfolioMetricsProcessor::new, Named.as("portfolio_metrics_result"));

        return streamsBuilder.build(streamsProperties);
    }

}
