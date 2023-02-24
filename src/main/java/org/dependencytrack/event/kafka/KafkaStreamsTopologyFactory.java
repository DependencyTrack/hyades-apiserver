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
import org.cyclonedx.model.Bom;
import org.dependencytrack.event.kafka.processor.MirrorVulnerabilityProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityScanResultProcessor;
import org.dependencytrack.event.kafka.serialization.JacksonSerde;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerde;
import org.dependencytrack.model.MetaModel;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;
import org.hyades.proto.vulnanalysis.v1.internal.ScanCompletion;
import org.hyades.proto.vulnanalysis.v1.internal.ScanCompletionStatus;

import java.util.Properties;
import java.util.UUID;

class KafkaStreamsTopologyFactory {

    Topology createTopology() {
        final var streamsBuilder = new StreamsBuilder();

        final var streamsProperties = new Properties();
        streamsProperties.put(StreamsConfig.TOPOLOGY_OPTIMIZATION_CONFIG, StreamsConfig.OPTIMIZE);

        final var vulnScanCommandSerde = new KafkaProtobufSerde<>(ScanCommand.parser());
        final var vulnScanCompletionSerde = new KafkaProtobufSerde<>(ScanCompletion.parser());
        final var vulnScanKeySerde = new KafkaProtobufSerde<>(ScanKey.parser());
        final var vulnScanResultSerde = new KafkaProtobufSerde<>(ScanResult.parser());

        final KStream<ScanKey, ScanCommand> vulnScanCommandStream = streamsBuilder
                .stream(KafkaTopic.VULN_ANALYSIS_COMPONENT.getName(), Consumed
                        .with(vulnScanKeySerde, vulnScanCommandSerde)
                        .withName("consume_from_%s_topic".formatted(KafkaTopic.VULN_ANALYSIS_COMPONENT.getName())));

        final KStream<ScanKey, ScanResult> vulnScanResultStream = streamsBuilder
                .stream(KafkaTopic.VULN_ANALYSIS_RESULT.getName(), Consumed
                        .with(vulnScanKeySerde, vulnScanResultSerde)
                        .withName("consume_from_%s_topic".formatted(KafkaTopic.VULN_ANALYSIS_RESULT)));

        // Count the components submitted for vulnerability analysis under the same scan token,
        // and persist this number in a KTable.
        final KTable<String, Long> expectedVulnScanResultsTable = vulnScanCommandStream
                .selectKey((scanKey, component) -> scanKey.getCorrelationId(),
                        Named.as("re-key_component_to_correlation_id"))
                .groupByKey(Grouped.with(Serdes.String(), vulnScanCommandSerde))
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
                        .with(Serdes.UUID(), vulnScanResultSerde)
                        .withName("vuln-scan-result-by-component-uuid"))
                .process(VulnerabilityScanResultProcessor::new, Named.as("process_vuln_scan_result"));
        // TODO: Kick off policy evaluation when vulnerability analysis completed,
        // as some policies may check for things like severities etc.

        // Count the processed vulnerability scanner results with status COMPLETE that have been emitted for the same scan token.
        final KTable<String, Long> completedProcessedVulnScanResultsTable = processedVulnScanResulStream
                .selectKey((scanKey, scanResult) -> scanKey.getCorrelationId(),
                        Named.as("re-key_vuln_scan_result_to_scan_token"))
                .groupByKey(Grouped
                        .with(Serdes.String(), vulnScanResultSerde)
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
                .join(expectedVulnScanResultsTable, (received, expected) -> expected - received, Joined
                        .with(Serdes.String(), Serdes.Long(), Serdes.Long())
                        .withName("join_result_counts"))
                .mapValues(count -> count == 0
                                ? ScanCompletion.newBuilder().setStatus(ScanCompletionStatus.SCAN_COMPLETION_STATUS_COMPLETE).build()
                                : ScanCompletion.newBuilder().setStatus(ScanCompletionStatus.SCAN_COMPLETION_STATUS_PENDING).build(),
                        Named.as("map_to_completion_status"))
                .toTable(Named.as("materialize_vuln_scan_completion_status"), Materialized
                        .<String, ScanCompletion, KeyValueStore<Bytes, byte[]>>as(KafkaStateStoreNames.VULNERABILITY_SCAN_COMPLETION)
                        .withKeySerde(Serdes.String())
                        .withValueSerde(vulnScanCompletionSerde)
                        .withStoreType(Materialized.StoreType.ROCKS_DB));

        streamsBuilder
                .stream(KafkaTopic.REPO_META_ANALYSIS_RESULT.getName(),
                        Consumed.with(Serdes.UUID(), new JacksonSerde<>(MetaModel.class))
                                .withName("consume_from_%s_topic".formatted(KafkaTopic.REPO_META_ANALYSIS_RESULT)))
                .process(RepositoryMetaResultProcessor::new, Named.as("process_repo_meta_analysis_result"));

        streamsBuilder
                .stream(KafkaTopic.NEW_VULNERABILITY.getName(),
                        Consumed.with(Serdes.String(), new JacksonSerde<>(Bom.class))
                                .withName("consume_from_%s_topic".formatted(KafkaTopic.NEW_VULNERABILITY)))
                .process(MirrorVulnerabilityProcessor::new, Named.as("process_mirror_vulnerability"));

        return streamsBuilder.build(streamsProperties);
    }

}
