package org.dependencytrack.event.kafka.processor;


import net.mguenther.kafka.junit.ExternalKafkaCluster;
import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.ReadKeyValues;
import net.mguenther.kafka.junit.SendKeyValues;
import net.mguenther.kafka.junit.TopicConfig;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.BooleanDeserializer;
import org.apache.kafka.common.serialization.IntegerDeserializer;
import org.apache.kafka.common.serialization.LongSerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.event.kafka.processor.api.RecordProcessor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.redpanda.RedpandaContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.List;

import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class KafkaProcessorTest {

    @Rule
    public RedpandaContainer container = new RedpandaContainer(DockerImageName
            .parse("docker.redpanda.com/vectorized/redpanda:v23.2.13"));

    ExternalKafkaCluster kafka;

    @Before
    public void setUp() {
        kafka = ExternalKafkaCluster.at(container.getBootstrapServers());
    }

    @Test
    public void testSingleRecordProcessor() throws Exception {
        kafka.createTopic(TopicConfig.withName("input"));
        kafka.createTopic(TopicConfig.withName("output"));

        final RecordProcessor<String, Long, Integer, Boolean> recordProcessor =
                record -> List.of(new ProducerRecord<>("output", 2, true));

        final var processorFactory = new KafkaProcessorFactory();
        try (final KafkaProcessor processor = processorFactory.createProcessor(recordProcessor)) {
            processor.start();

            kafka.send(SendKeyValues.to("input", List.of(new KeyValue<>("foo", 123L)))
                    .with(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName())
                    .with(VALUE_SERIALIZER_CLASS_CONFIG, LongSerializer.class.getName()));
        }

        await()
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final List<KeyValue<Integer, Boolean>> records = kafka.read(ReadKeyValues.from("output", Integer.class, Boolean.class)
                            .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, IntegerDeserializer.class.getName())
                            .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, BooleanDeserializer.class.getName()));

                    assertThat(records).hasSize(1);
                });
    }

}