package org.dependencytrack.event.kafka.processor;

import org.apache.kafka.common.serialization.UUIDDeserializer;
import org.apache.kafka.common.serialization.UUIDSerializer;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyTestDriver;
import org.apache.kafka.streams.test.TestRecord;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.serialization.JacksonDeserializer;
import org.dependencytrack.event.kafka.serialization.JacksonSerializer;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.tasks.repositories.MetaModel;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class RepositoryMetaResultProcessorTest extends PersistenceCapableTest {

    private TopologyTestDriver testDriver;
    private TestInputTopic<UUID, MetaModel> inputTopic;

    @Before
    public void setUp() {
        final var topology = new Topology();
        topology.addSource("sourceProcessor",
                new UUIDDeserializer(), new JacksonDeserializer<>(MetaModel.class), "input-topic");
        topology.addProcessor("metaResultProcessor",
                RepositoryMetaResultProcessor::new, "sourceProcessor");

        testDriver = new TopologyTestDriver(topology);
        inputTopic = testDriver.createInputTopic("input-topic",
                new UUIDSerializer(), new JacksonSerializer<>());
    }

    @After
    public void tearDown() {
        if (testDriver != null) {
            testDriver.close();
        }
    }

    @Test
    public void processNewMetaModelTest() {
        final var testStartTime = new Date();

        final var component = new Component();
        component.setUuid(UUID.randomUUID());
        component.setPurl("pkg:maven/foo/bar@1.2.3");

        final var metaModel = new MetaModel(component);
        metaModel.setLatestVersion("1.2.4");
        metaModel.setPublishedTimestamp(new Date());

        inputTopic.pipeInput(component.getUuid(), metaModel);

        final RepositoryMetaComponent metaComponent =
                qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "foo", "bar");
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualTo(metaModel.getPublishedTimestamp());
        assertThat(metaComponent.getLastCheck()).isAfterOrEqualTo(testStartTime);
    }

    @Test
    public void processWithoutComponentDetailsTest() {
        final var component = new Component();
        component.setUuid(UUID.randomUUID());

        final var metaModel = new MetaModel(component);
        metaModel.setLatestVersion("1.2.4");
        metaModel.setPublishedTimestamp(new Date());

        inputTopic.pipeInput(component.getUuid(), metaModel);

        final RepositoryMetaComponent metaComponent =
                qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "foo", "bar");
        assertThat(metaComponent).isNull();
    }

    @Test
    public void processUpdateExistingMetaModelTest() {
        final var testStartTime = new Date();

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("1.0.0");
        metaComponent.setPublished(Date.from(Instant.now().minus(Duration.ofDays(1))));
        metaComponent.setLastCheck(Date.from(Instant.now().minus(Duration.ofMinutes(5))));
        qm.persist(metaComponent);

        final var component = new Component();
        component.setUuid(UUID.randomUUID());
        component.setPurl("pkg:maven/foo/bar@1.2.3");

        final var metaModel = new MetaModel(component);
        metaModel.setLatestVersion("1.2.4");
        metaModel.setPublishedTimestamp(new Date());

        inputTopic.pipeInput(component.getUuid(), metaModel);

        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualTo(metaModel.getPublishedTimestamp());
        assertThat(metaComponent.getLastCheck()).isAfterOrEqualTo(testStartTime);
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

        final var component = new Component();
        component.setUuid(UUID.randomUUID());
        component.setPurl("pkg:maven/foo/bar@1.2.3");

        final var metaModel = new MetaModel(component);
        metaModel.setLatestVersion("1.2.4");
        metaModel.setPublishedTimestamp(new Date());

        // Pipe in a record that was produced 10 seconds ago, 5 seconds before metaComponent's lastCheck.
        inputTopic.pipeInput(new TestRecord<>(component.getUuid(), metaModel, Instant.now().minusSeconds(10)));

        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.5"); // Must not have been updated
        assertThat(metaComponent.getPublished()).isNotEqualTo(metaModel.getPublishedTimestamp()); // Must not have been updated
        assertThat(metaComponent.getLastCheck()).isBefore(testStartTime); // Must not have been updated
    }

}