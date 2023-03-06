package org.dependencytrack.event.kafka;

import net.mguenther.kafka.junit.ExternalKafkaCluster;
import net.mguenther.kafka.junit.TopicConfig;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.StreamsConfig;
import org.dependencytrack.PersistenceCapableTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.testcontainers.redpanda.RedpandaContainer;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;

abstract class KafkaStreamsTest extends PersistenceCapableTest {

    @Rule
    public RedpandaContainer container = new RedpandaContainer(DockerImageName
            .parse("docker.redpanda.com/vectorized/redpanda:v22.3.10"));

    KafkaStreams kafkaStreams;
    ExternalKafkaCluster kafka;
    private Path kafkaStreamsStateDirectory;

    @Before
    public void setUp() throws Exception {
        kafka = ExternalKafkaCluster.at(container.getBootstrapServers());

        kafka.createTopic(TopicConfig
                .withName(KafkaTopic.VULN_ANALYSIS_COMPONENT.getName())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));
        kafka.createTopic(TopicConfig
                .withName(KafkaTopic.VULN_ANALYSIS_RESULT.getName())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));
        kafka.createTopic(TopicConfig
                .withName(KafkaTopic.REPO_META_ANALYSIS_RESULT.getName())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));
        kafka.createTopic(TopicConfig
                .withName(KafkaTopic.NEW_VULNERABILITY.getName())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));

        kafka.createTopic(TopicConfig
                .withName(KafkaTopic.PROJECT_METRICS.getName())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));

        kafka.createTopic(TopicConfig
                .withName(KafkaTopic.PORTFOLIO_METRICS.getName())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));

        kafkaStreamsStateDirectory = Files.createTempDirectory(getClass().getSimpleName());

        final var streamsConfig = KafkaStreamsInitializer.getDefaultProperties();
        streamsConfig.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, container.getBootstrapServers());
        streamsConfig.put(StreamsConfig.APPLICATION_ID_CONFIG, getClass().getSimpleName());
        streamsConfig.put(StreamsConfig.STATE_DIR_CONFIG, kafkaStreamsStateDirectory.toString());
        streamsConfig.put(StreamsConfig.NUM_STREAM_THREADS_CONFIG, "3");

        kafkaStreams = new KafkaStreams(new KafkaStreamsTopologyFactory().createTopology(), streamsConfig);
        kafkaStreams.start();

        assertConditionWithTimeout(() -> KafkaStreams.State.RUNNING == kafkaStreams.state(), Duration.ofSeconds(5));
    }

    @After
    public void tearDown() {
        if (kafkaStreams != null) {
            kafkaStreams.close();
        }
        if (kafkaStreamsStateDirectory != null) {
            kafkaStreamsStateDirectory.toFile().delete();
        }
    }

}
