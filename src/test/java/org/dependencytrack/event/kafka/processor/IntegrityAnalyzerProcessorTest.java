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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIntegrityAnalysis;
import org.dependencytrack.model.Project;
import org.hyades.proto.repometaanalysis.v1.HashMatchStatus;
import org.hyades.proto.repometaanalysis.v1.IntegrityResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrityAnalyzerProcessorTest extends PersistenceCapableTest {

    private TopologyTestDriver testDriver;
    private TestInputTopic<String, IntegrityResult> inputTopic;

    @Before
    public void setUp() {
        final var topology = new Topology();
        topology.addSource("sourceProcessor",
                new StringDeserializer(), new KafkaProtobufDeserializer<>(IntegrityResult.parser()), "input-topic");
        topology.addProcessor("integrityResultProcessor",
                IntegrityAnalysisResultProcessor::new, "sourceProcessor");

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
    public void processNewIntegrityResult() {
        Project project = new Project();
        project.setName("testproject");
        Component component = new Component();
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2");
        component.setProject(project);
        component.setMd5("test");
        component.setSha1("test3");
        component.setSha256("test465");
        component.setName("testComponent");
        qm.createComponent(component, false);
        UUID uuid = qm.getObjectById(Component.class, 1).getUuid();
        final var result = IntegrityResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2")
                        .setComponentId(1)
                        .setUuid(uuid.toString()))
                .setSha1HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setRepository("testRepo")
                .setMd5HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setSha256HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(1639098000))
                .build();

        inputTopic.pipeInput("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", result);
        PersistenceManager pm = qm.getPersistenceManager();
        pm.newQuery(pm.newQuery(ComponentIntegrityAnalysis.class));
        ComponentIntegrityAnalysis persistentIntegrityResult = qm.getIntegrityAnalysisComponentResult(uuid, "testRepo", 1);
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult.getRepositoryIdentifier()).isEqualTo("testRepo");
        assertThat(persistentIntegrityResult.isSha256HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
        assertThat(persistentIntegrityResult.isMd5HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
        assertThat(persistentIntegrityResult.isSha1HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
    }

    @Test
    public void processNewIntegrityResultComponentMissingHash() {
        Project project = new Project();
        project.setName("testproject");
        Component component = new Component();
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2");
        component.setProject(project);
        component.setName("testComponent");
        qm.createComponent(component, false);
        UUID uuid = qm.getObjectById(Component.class, 1).getUuid();

        final var result = IntegrityResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2")
                        .setComponentId(1)
                        .setUuid(uuid.toString()))
                .setSha1HashMatch(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH)
                .setRepository("testRepo")
                .setMd5HashMatch(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH)
                .setSha256HashMatch(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH)
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(1639098000))
                .build();

        inputTopic.pipeInput("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", result);
        PersistenceManager pm = qm.getPersistenceManager();
        pm.newQuery(pm.newQuery(ComponentIntegrityAnalysis.class));
        ComponentIntegrityAnalysis persistentIntegrityResult = qm.getIntegrityAnalysisComponentResult(uuid, "testRepo", 1);
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult.getRepositoryIdentifier()).isEqualTo("testRepo");
        assertThat(persistentIntegrityResult.isIntegrityCheckPassed()).isFalse();
        assertThat(persistentIntegrityResult.isSha256HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH.toString());
        assertThat(persistentIntegrityResult.isMd5HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH.toString());
        assertThat(persistentIntegrityResult.isSha1HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH.toString());
    }

    @Test
    public void processNewIntegrityResultSourceMissingHash() {
        Project project = new Project();
        project.setName("testproject");
        Component component = new Component();
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2");
        component.setProject(project);
        component.setMd5("test");
        component.setSha1("test3");
        component.setSha256("test465");
        component.setName("testComponent");
        qm.createComponent(component, false);
        UUID uuid = qm.getObjectById(Component.class, 1).getUuid();

        final var result = IntegrityResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2")
                        .setComponentId(1)
                        .setUuid(uuid.toString()))
                .setSha1HashMatch(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN)
                .setRepository("testRepo")
                .setMd5HashMatch(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN)
                .setSha256HashMatch(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN)
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(1639098000))
                .build();

        inputTopic.pipeInput("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", result);
        PersistenceManager pm = qm.getPersistenceManager();
        pm.newQuery(pm.newQuery(ComponentIntegrityAnalysis.class));
        ComponentIntegrityAnalysis persistentIntegrityResult = qm.getIntegrityAnalysisComponentResult(uuid, "testRepo", 1);
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult.getRepositoryIdentifier()).isEqualTo("testRepo");
        assertThat(persistentIntegrityResult.isIntegrityCheckPassed()).isFalse();
        assertThat(persistentIntegrityResult.isSha256HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN.toString());
        assertThat(persistentIntegrityResult.isMd5HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN.toString());
        assertThat(persistentIntegrityResult.isSha1HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN.toString());
    }

    @Test
    public void processWithoutComponentDetailsTest() {
        final var result = IntegrityResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2")
                        .setComponentId(1)
                        .setUuid(UUID.randomUUID().toString()))
                .setSha1HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setRepository("testRepo")
                .setMd5HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setSha256HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(Instant.now().getEpochSecond()))
                .build();

        inputTopic.pipeInput("foo", result);

        final Query<ComponentIntegrityAnalysis> query = qm.getPersistenceManager().newQuery(ComponentIntegrityAnalysis.class);
        query.setResult("count(this)");

        assertThat(query.executeResultUnique(Long.class)).isZero();
    }

    @Test
    public void processUpdateExistingMetaModelTest() {
        Project project = new Project();
        project.setName("testproject");
        Component component = new Component();
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2");
        component.setProject(project);
        component.setMd5("test");
        component.setSha1("test3");
        component.setSha256("test465");
        component.setName("testComponent");
        qm.createComponent(component, false);
        UUID uuid = qm.getObjectById(Component.class, 1).getUuid();
        final var integrityAnalysisComponent = new ComponentIntegrityAnalysis();
        integrityAnalysisComponent.setComponent(component);
        integrityAnalysisComponent.setIntegrityCheckPassed(false);
        integrityAnalysisComponent.setRepositoryIdentifier("testRepo");
        integrityAnalysisComponent.setLastCheck(new Date(1639098001));
        integrityAnalysisComponent.setId(2);
        integrityAnalysisComponent.setMd5HashMatched(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        integrityAnalysisComponent.setSha1HashMatched(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        integrityAnalysisComponent.setSha256HashMatched(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        qm.persist(integrityAnalysisComponent);
        final var result = IntegrityResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2")
                        .setComponentId(1)
                        .setUuid(uuid.toString()))
                .setSha1HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setRepository("testRepo")
                .setMd5HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setSha256HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(1639098001))
                .build();

        inputTopic.pipeInput("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", result);

        qm.getPersistenceManager().refresh(integrityAnalysisComponent);
        assertThat(integrityAnalysisComponent).isNotNull();
        assertThat(integrityAnalysisComponent.getRepositoryIdentifier()).isEqualTo("testRepo");
        assertThat(integrityAnalysisComponent.isSha256HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
        assertThat(integrityAnalysisComponent.isMd5HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
        assertThat(integrityAnalysisComponent.isSha1HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
    }

    @Test
    public void processNewIntegrityResultFail() {
        Project project = new Project();
        project.setName("testproject");
        Component component = new Component();
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2");
        component.setProject(project);
        component.setMd5("test");
        component.setSha1("test3");
        component.setSha256("test465");
        component.setName("testComponent");
        qm.createComponent(component, false);
        UUID uuid = qm.getObjectById(Component.class, 1).getUuid();

        final var result = IntegrityResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2")
                        .setComponentId(1)
                        .setUuid(uuid.toString()))
                .setSha1HashMatch(HashMatchStatus.HASH_MATCH_STATUS_FAIL)
                .setRepository("testRepo")
                .setMd5HashMatch(HashMatchStatus.HASH_MATCH_STATUS_FAIL)
                .setSha256HashMatch(HashMatchStatus.HASH_MATCH_STATUS_FAIL)
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(1639098000))
                .build();

        inputTopic.pipeInput("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", result);
        ComponentIntegrityAnalysis persistentIntegrityResult = qm.getIntegrityAnalysisComponentResult(uuid, "testRepo", 1);
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult).isNotNull();
        assertThat(persistentIntegrityResult.getRepositoryIdentifier()).isEqualTo("testRepo");
        assertThat(persistentIntegrityResult.isIntegrityCheckPassed()).isFalse();
        assertThat(persistentIntegrityResult.isSha256HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        assertThat(persistentIntegrityResult.isMd5HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        assertThat(persistentIntegrityResult.isSha1HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
    }

    @Test
    public void processUpdateOutOfOrderMetaModelTest() {
        final var testStartTime = new Date();

        final var integrityAnalysisComponent = new ComponentIntegrityAnalysis();
        Project project = new Project();
        project.setName("testproject");
        Component component = new Component();
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2");
        component.setProject(project);
        component.setMd5("test");
        component.setSha1("test3");
        component.setSha256("test465");
        component.setName("testComponent");
        qm.createComponent(component, false);
        UUID uuid = qm.getObjectById(Component.class, 1).getUuid();
        integrityAnalysisComponent.setComponent(component);
        integrityAnalysisComponent.setIntegrityCheckPassed(false);
        integrityAnalysisComponent.setRepositoryIdentifier("testRepo");
        integrityAnalysisComponent.setLastCheck(new Date(1639098001));
        integrityAnalysisComponent.setId(2);
        integrityAnalysisComponent.setMd5HashMatched(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        integrityAnalysisComponent.setSha1HashMatched(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        integrityAnalysisComponent.setSha256HashMatched(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        integrityAnalysisComponent.setLastCheck(Date.from(Instant.now().minusSeconds(5)));
        qm.persist(integrityAnalysisComponent);

        final var published = Instant.now();

        final var result = IntegrityResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2")
                        .setComponentId(1)
                        .setUuid(uuid.toString()))
                .setSha1HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setRepository("testRepo")
                .setMd5HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setSha256HashMatch(HashMatchStatus.HASH_MATCH_STATUS_PASS)
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .build();

        // Pipe in a record that was produced 10 seconds ago, 5 seconds before integrity analysis's lastCheck.
        inputTopic.pipeInput(new TestRecord<>("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", result, Instant.now().minusSeconds(10)));

        qm.getPersistenceManager().refresh(integrityAnalysisComponent);
        assertThat(integrityAnalysisComponent).isNotNull();
        assertThat(integrityAnalysisComponent.getRepositoryIdentifier()).isEqualTo("testRepo");
        assertThat(integrityAnalysisComponent.isIntegrityCheckPassed()).isFalse();
        assertThat(integrityAnalysisComponent.isSha256HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        assertThat(integrityAnalysisComponent.isMd5HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        assertThat(integrityAnalysisComponent.isSha1HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_FAIL.toString());
        assertThat(integrityAnalysisComponent.getLastCheck()).isBefore(testStartTime); // Must not have been updated
    }

}