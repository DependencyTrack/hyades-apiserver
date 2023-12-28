package org.dependencytrack.event.kafka.processor.api;

import alpine.Config;
import net.mguenther.kafka.junit.ExternalKafkaCluster;
import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.SendKeyValues;
import net.mguenther.kafka.junit.TopicConfig;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.redpanda.RedpandaContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class RecordProcessorManagerTest {

    @Rule
    public RedpandaContainer container = new RedpandaContainer(DockerImageName
            .parse("docker.redpanda.com/vectorized/redpanda:v23.2.13"));

    ExternalKafkaCluster kafka;
    Config configMock;

    @Before
    public void setUp() {
        kafka = ExternalKafkaCluster.at(container.getBootstrapServers());

        configMock = mock(Config.class);
        doReturn(container.getBootstrapServers())
                .when(configMock).getProperty(eq(ConfigKey.KAFKA_BOOTSTRAP_SERVERS));
    }

    @Test
    public void test() throws Exception {
        final var inputTopic = new Topic<>("input", Serdes.String(), Serdes.String());
        kafka.createTopic(TopicConfig.withName(inputTopic.name()));

        final var recordsProcessed = new AtomicInteger(0);

        doReturn(Map.of(
                "kafka.processor.foo.processing.order", "key",
                "kafka.processor.foo.max.concurrency", "5",
                "kafka.processor.foo.consumer.auto.offset.reset", "earliest"
        )).when(configMock).getPassThroughProperties(eq("kafka.processor.foo.consumer"));

        final SingleRecordProcessor<String, String> recordProcessor =
                record -> recordsProcessed.incrementAndGet();

        try (final var processorManager = new RecordProcessorManager(configMock)) {
            processorManager.register("foo", recordProcessor, inputTopic);

            for (int i = 0; i < 100; i++) {
                kafka.send(SendKeyValues.to("input", List.of(new KeyValue<>("foo" + i, "bar" + i)))
                        .with(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName())
                        .with(VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName()));
            }

            processorManager.startAll();

            await("Record Processing")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(recordsProcessed).hasValue(100));
        }
    }

    @Test
    public void testBatchProcessor() throws Exception {
        final var inputTopic = new Topic<>("input", Serdes.String(), Serdes.String());
        kafka.createTopic(TopicConfig.withName(inputTopic.name()).withNumberOfPartitions(6));

        final var recordsProcessed = new AtomicInteger(0);
        final var actualBatchSizes = new ConcurrentLinkedQueue<>();

        doReturn(Map.of(
                "kafka.processor.foo.processing.order", "key",
                "kafka.processor.foo.max.batch.size", "100"
        )).when(configMock).getPassThroughProperties(eq("kafka.processor.foo"));
        doReturn(Map.of("kafka.processor.foo.consumer.auto.offset.reset", "earliest"))
                .when(configMock).getPassThroughProperties(eq("kafka.processor.foo.consumer"));

        final BatchRecordProcessor<String, String> recordProcessor = records -> {
            recordsProcessed.addAndGet(records.size());
            actualBatchSizes.add(records.size());
        };

        try (final var processorManager = new RecordProcessorManager(configMock)) {
            processorManager.register("foo", recordProcessor, inputTopic);

            for (int i = 0; i < 1_000; i++) {
                kafka.send(SendKeyValues.to("input", List.of(new KeyValue<>("foo" + i, "bar" + i)))
                        .with(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName())
                        .with(VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName()));
            }

            processorManager.startAll();

            await("Record Processing")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(recordsProcessed).hasValue(1_000));

            assertThat(actualBatchSizes).containsOnly(100);
        }
    }

}