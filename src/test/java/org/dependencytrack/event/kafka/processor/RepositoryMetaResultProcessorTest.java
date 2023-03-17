package org.dependencytrack.event.kafka.processor;

import com.google.protobuf.Timestamp;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyTestDriver;
import org.apache.kafka.streams.test.TestRecord;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufDeserializer;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.hyades.proto.repometaanalysis.v1.AnalysisResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.Query;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class RepositoryMetaResultProcessorTest extends PersistenceCapableTest {

    private TopologyTestDriver testDriver;
    private TestInputTopic<String, AnalysisResult> inputTopic;

    @Before
    public void setUp() {
        final var topology = new Topology();
        topology.addSource("sourceProcessor",
                new StringDeserializer(), new KafkaProtobufDeserializer<>(AnalysisResult.parser()), "input-topic");
        topology.addProcessor("metaResultProcessor",
                RepositoryMetaResultProcessor::new, "sourceProcessor");

        testDriver = new TopologyTestDriver(topology);
        inputTopic = testDriver.createInputTopic("input-topic",
                new StringSerializer(), new KafkaProtobufSerializer<>());
    }

    @After
    public void tearDown() {
        if (testDriver != null) {
            testDriver.close();
        }
    }

    @Test
    public void processNewMetaModelTest() {
        final var published = Instant.now().minus(5, ChronoUnit.MINUTES);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .build();

        inputTopic.pipeInput("pkg:maven/foo/bar", result);

        final RepositoryMetaComponent metaComponent =
                qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "foo", "bar");
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualToIgnoringMillis(Date.from(published));
    }

    @Test
    public void processWithoutComponentDetailsTest() {
        final var result = AnalysisResult.newBuilder()
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(Instant.now().getEpochSecond()))
                .build();

        inputTopic.pipeInput("foo", result);

        final Query<RepositoryMetaComponent> query = qm.getPersistenceManager().newQuery(RepositoryMetaComponent.class);
        query.setResult("count(this)");

        assertThat(query.executeResultUnique(Long.class)).isZero();
    }

    @Test
    public void processUpdateExistingMetaModelTest() {
        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("1.0.0");
        metaComponent.setPublished(Date.from(Instant.now().minus(Duration.ofDays(1))));
        metaComponent.setLastCheck(Date.from(Instant.now().minus(Duration.ofMinutes(5))));
        qm.persist(metaComponent);

        final var published = Instant.now();

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .build();

        inputTopic.pipeInput("pkg:maven/foo/bar", result);

        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualToIgnoringMillis(Date.from(published));
    }

    @Test
    public void processUpdateOutOfOrderMetaModelTest() {
        final var testStartTime = new Date();

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("1.2.5");
        metaComponent.setPublished(Date.from(Instant.now().minus(Duration.ofDays(1))));
        metaComponent.setLastCheck(Date.from(Instant.now().minusSeconds(5)));
        qm.persist(metaComponent);

        final var published = Instant.now();

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .build();

        // Pipe in a record that was produced 10 seconds ago, 5 seconds before metaComponent's lastCheck.
        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now().minusSeconds(10)));

        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.5"); // Must not have been updated
        assertThat(metaComponent.getPublished()).isNotEqualTo(Date.from(published)); // Must not have been updated
        assertThat(metaComponent.getLastCheck()).isBefore(testStartTime); // Must not have been updated
    }

}