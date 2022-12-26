package org.dependencytrack.event.kafka;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.Named;
import org.dependencytrack.event.kafka.dto.AnalyzerConfig;
import org.dependencytrack.event.kafka.dto.VulnerabilityResult;
import org.dependencytrack.event.kafka.processor.ComponentAnalyzerConfigProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityResultProcessor;
import org.dependencytrack.event.kafka.serialization.JacksonSerde;
import org.dependencytrack.tasks.repositories.MetaModel;

class KafkaStreamsTopologyFactory {

    Topology createTopology() {
        final var streamsBuilder = new StreamsBuilder();

        streamsBuilder
                .stream(KafkaTopic.REPO_META_ANALYSIS_RESULT.getName(),
                        Consumed.with(Serdes.UUID(), new JacksonSerde<>(MetaModel.class))
                                .withName("consume_from_%s_topic".formatted(KafkaTopic.REPO_META_ANALYSIS_RESULT)))
                .process(RepositoryMetaResultProcessor::new, Named.as("process_repo_meta_analysis_result"));

        streamsBuilder
                .stream(KafkaTopic.VULN_ANALYSIS_RESULT.getName(),
                        Consumed.with(Serdes.UUID(), new JacksonSerde<>(VulnerabilityResult.class))
                                .withName("consume_from_%s_topic".formatted(KafkaTopic.VULN_ANALYSIS_RESULT)))
                .process(VulnerabilityResultProcessor::new, Named.as("process_vuln_analysis_result"));

        streamsBuilder
                .stream(KafkaTopic.VULN_ANALYSIS_INFO.getName(),
                        Consumed.with(Serdes.UUID(), new JacksonSerde<>(AnalyzerConfig.class))
                                .withName("consume_from_%s_topic".formatted(KafkaTopic.VULN_ANALYSIS_INFO)))
                .process(ComponentAnalyzerConfigProcessor::new, Named.as("process_vuln_analysis_config"));


        return streamsBuilder.build();
    }

}
