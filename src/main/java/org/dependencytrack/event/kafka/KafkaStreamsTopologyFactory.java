package org.dependencytrack.event.kafka;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.utils.Bytes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.Grouped;
import org.apache.kafka.streams.kstream.Joined;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.KTable;
import org.apache.kafka.streams.kstream.Materialized;
import org.apache.kafka.streams.kstream.Named;
import org.apache.kafka.streams.kstream.Repartitioned;
import org.apache.kafka.streams.state.KeyValueStore;
import org.dependencytrack.event.kafka.processor.MirrorVulnerabilityProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityScanResultProcessor;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerde;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;
import org.hyades.proto.vulnanalysis.v1.internal.ScanCompletion;
import org.hyades.proto.vulnanalysis.v1.internal.ScanCompletionStatus;
import org.hyades.proto.vulnanalysis.v1.internal.ScanResultsExpectedReceived;

import java.util.Properties;
import java.util.UUID;

class KafkaStreamsTopologyFactory {

    Topology createTopology() {
        final var streamsBuilder = new StreamsBuilder();

        final var streamsProperties = new Properties();
        streamsProperties.put(StreamsConfig.TOPOLOGY_OPTIMIZATION_CONFIG, StreamsConfig.OPTIMIZE);

        final var vulnScanCompletionSerde = new KafkaProtobufSerde<>(ScanCompletion.parser());

        final KStream<ScanKey, ScanCommand> vulnScanCommandStream = streamsBuilder
                .stream(KafkaTopics.VULN_ANALYSIS_COMMAND.name(), Consumed
                        .with(KafkaTopics.VULN_ANALYSIS_COMMAND.keySerde(), KafkaTopics.VULN_ANALYSIS_COMMAND.valueSerde())
                        .withName("consume_from_%s_topic".formatted(KafkaTopics.VULN_ANALYSIS_COMMAND.name())));

        final KStream<ScanKey, ScanResult> vulnScanResultStream = streamsBuilder
                .stream(KafkaTopics.VULN_ANALYSIS_RESULT.name(), Consumed
                        .with(KafkaTopics.VULN_ANALYSIS_RESULT.keySerde(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("consume_from_%s_topic".formatted(KafkaTopics.VULN_ANALYSIS_RESULT.name())));

        // Count the components submitted for vulnerability analysis under the same scan token,
        // and persist this number in a KTable.
        final KTable<String, Long> expectedVulnScanResultsTable = vulnScanCommandStream
                .selectKey((scanKey, component) -> scanKey.getScanToken(),
                        Named.as("re-key_component_to_scan_token"))
                .groupByKey(Grouped.with(Serdes.String(), KafkaTopics.VULN_ANALYSIS_COMMAND.valueSerde()))
                .count(Named.as("count_components"), Materialized
                        .<String, Long, KeyValueStore<Bytes, byte[]>>as(KafkaStateStoreNames.EXPECTED_VULNERABILITY_SCAN_RESULTS)
                        .withKeySerde(Serdes.String())
                        .withValueSerde(Serdes.Long())
                        .withStoreType(Materialized.StoreType.ROCKS_DB));

        // Actually process the vulnerabilities reported by the scanners.
        // Re-key the result stream to component UUIDs to ensure that results
        // for the same component are processed in a serial fashion.
        //
        // Results with status COMPLETE are re-keyed back to scan keys
        // and forwarded, all other results are dropped after successful processing.
        final KStream<ScanKey, ScanResult> processedVulnScanResulStream = vulnScanResultStream
                .selectKey((scanKey, scanResult) -> UUID.fromString(scanKey.getComponentUuid()),
                        Named.as("re-key_vuln_scan_result_to_component_uuid"))
                .repartition(Repartitioned
                        .with(Serdes.UUID(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("vuln-scan-result-by-component-uuid"))
                .process(VulnerabilityScanResultProcessor::new, Named.as("process_vuln_scan_result"));
        // TODO: Kick off policy evaluation when vulnerability analysis completed,
        // as some policies may check for things like severities etc.

        // Count the processed vulnerability scanner results with status COMPLETE that have been emitted for the same scan token.
        final KTable<String, Long> completedProcessedVulnScanResultsTable = processedVulnScanResulStream
                .selectKey((scanKey, scanResult) -> scanKey.getScanToken(),
                        Named.as("re-key_vuln_scan_result_to_scan_token"))
                .groupByKey(Grouped
                        .with(Serdes.String(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("completed-vuln-scans-by-scan-token"))
                .count(Named.as("count_completed_vuln_scans"), Materialized
                        .<String, Long, KeyValueStore<Bytes, byte[]>>as(KafkaStateStoreNames.RECEIVED_VULNERABILITY_SCAN_RESULTS)
                        .withKeySerde(Serdes.String())
                        .withValueSerde(Serdes.Long())
                        .withStoreType(Materialized.StoreType.ROCKS_DB)
                        .withCachingDisabled()); // Forward all changes to stream

        // Join the number of processed COMPLETE events with the KTable holding the number of components submitted for analysis.
        // If the count of received COMPLETE events is greater than or equal to the number of components submitted,
        // the scan overall can be considered to be completed.
        completedProcessedVulnScanResultsTable
                .toStream(Named.as("stream_received_vuln_scan_result_count"))
                .join(expectedVulnScanResultsTable,
                        (received, expected) -> ScanResultsExpectedReceived.newBuilder()
                                .setReceived(received)
                                .setExpected(expected)
                                .build(),
                        Joined.with(Serdes.String(), Serdes.Long(), Serdes.Long())
                                .withName("join_result_counts"))
                .mapValues(expectedReceived -> ScanCompletion.newBuilder()
                                .setResults(expectedReceived)
                                .setStatus(expectedReceived.getExpected() - expectedReceived.getReceived() == 0
                                        ? ScanCompletionStatus.SCAN_COMPLETION_STATUS_COMPLETE
                                        : ScanCompletionStatus.SCAN_COMPLETION_STATUS_PENDING
                                )
                                .build(),
                        Named.as("map_to_completion_status"))
                .toTable(Named.as("materialize_vuln_scan_completion_status"), Materialized
                        .<String, ScanCompletion, KeyValueStore<Bytes, byte[]>>as(KafkaStateStoreNames.VULNERABILITY_SCAN_COMPLETION)
                        .withKeySerde(Serdes.String())
                        .withValueSerde(vulnScanCompletionSerde)
                        .withStoreType(Materialized.StoreType.ROCKS_DB));

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
