package org.dependencytrack.event.kafka;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.Named;
import org.dependencytrack.event.kafka.dto.VulnerabilityResult;
import org.dependencytrack.event.kafka.processor.VulnerabilityResultProcessor;
import org.dependencytrack.event.kafka.serialization.JacksonSerde;

class KafkaStreamsTopologyFactory {

    Topology createTopology() {
        final var streamsBuilder = new StreamsBuilder();

        streamsBuilder
                .stream(KafkaTopic.COMPONENT_VULNERABILITY_ANALYSIS_RESULT.getName(),
                        Consumed.with(Serdes.UUID(), new JacksonSerde<>(VulnerabilityResult.class))
                                .withName("consume_from_component-vuln-analysis-result_topic"))
                .process(VulnerabilityResultProcessor::new, Named.as("process_vuln_analysis_results"));

        return streamsBuilder.build();
    }

}
