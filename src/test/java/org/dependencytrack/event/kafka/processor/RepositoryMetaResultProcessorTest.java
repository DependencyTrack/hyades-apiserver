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
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.proto.repometaanalysis.v1.IntegrityMeta;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import javax.jdo.Query;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class RepositoryMetaResultProcessorTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    private TopologyTestDriver testDriver;
    private TestInputTopic<String, AnalysisResult> inputTopic;

    @Before
    public void setUp() {
        environmentVariables.set("INTEGRITY_CHECK_ENABLED", "true");
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
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
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
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
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
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
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

    @Test
    public void processUpdateIntegrityResultTest() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .setMetaSourceUrl("test").build())
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getUpdatedAt()).isNotNull();
        assertThat(analysis.getComponent().getPurl().toString()).isEqualTo("pkg:maven/foo/bar@1.2.3");
    }

    @Test
    public void testIntegrityCheckWhenComponentHashIsMissing() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setMetaSourceUrl("test").build())
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.NOT_AVAILABLE);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_UNKNOWN);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_UNKNOWN);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_UNKNOWN);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getUpdatedAt()).isNotNull();
        assertThat(analysis.getComponent().getPurl().toString()).isEqualTo("pkg:maven/foo/bar@1.2.3");
    }

    @Test
    public void testIntegrityAnalysisWillNotBePerformedIfNoIntegrityDataInResult() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis).isNull();
    }

    @Test
    public void testIntegrityCheckWillNotBeDoneIfComponentUuidAndIntegrityDataIsMissing() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                //component uuid has not been set
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis).isNull();
    }

    @Test
    public void testIntegrityIfResultHasIntegrityDataAndComponentUuidIsMissing() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .build())
                //component uuid has not been set
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis).isNotNull();
        assertThat(analysis.getComponent()).isEqualTo(c);
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
    }


    @Test
    public void testIntegrityCheckWillNotBeDoneIfComponentIsNotInDb() {

        UUID uuid = UUID.randomUUID();

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(uuid.toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))

                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(uuid);
        assertThat(analysis).isNull();
    }

    @Test
    public void testIntegrityCheckShouldReturnComponentHashMissing() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .setMetaSourceUrl("test").build())
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
    }

    @Test
    public void testIntegrityCheckShouldReturnComponentHashMissingAndMatchUnknown() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setMetaSourceUrl("test").build())
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.NOT_AVAILABLE);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
    }

    @Test
    public void testIntegrityCheckShouldFailIfNoHashMatch() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setUuid(uuid);

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setSha1("somevalue")
                        .setMd5("someothervalue")
                        .setMetaSourceUrl("test").build())
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("someothervalue");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("somevalue");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_FAILED);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_FAILED);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_FAILED);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
    }

    @Test
    public void processUpdateIntegrityResultNotAvailableTest() {
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);


        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMetaSourceUrl("test").build())
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isNull();
        assertThat(integrityMetaComponent.getSha1()).isNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.NOT_AVAILABLE);
    }

    @Test
    public void processUpdateOldIntegrityResultSent() {

        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(date);
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setRepositoryUrl("test1");
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e587982fbbd3").setMetaSourceUrl("test2").build())
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getLastFetch()).isEqualTo(date);
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test1");
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);
    }


    @Test
    public void processBothMetaModelAndIntegrityMeta() {
        final var published = Instant.now().minus(5, ChronoUnit.MINUTES);
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .setMetaSourceUrl("test").build())
                .build();

        inputTopic.pipeInput("pkg:maven/foo/bar", result);
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        final RepositoryMetaComponent metaComponent =
                qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "foo", "bar");
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualToIgnoringMillis(Date.from(published));

        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);
    }

    @Test
    public void processUpdateIntegrityResultNotSentTest() {
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);


        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .build();

        inputTopic.pipeInput(new TestRecord<>("pkg:maven/foo/bar@1.2.3", result, Instant.now()));
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isNull();
        assertThat(integrityMetaComponent.getSha1()).isNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isNull();
        assertThat(integrityMetaComponent.getLastFetch()).isEqualTo(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.IN_PROGRESS);
    }
}