package org.dependencytrack.event.kafka;

import org.apache.kafka.common.serialization.UUIDSerializer;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyTestDriver;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.dto.AnalyzerConfig;
import org.dependencytrack.event.kafka.dto.VulnerabilityResult;
import org.dependencytrack.event.kafka.serialization.JacksonSerializer;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.repositories.MetaModel;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.dependencytrack.util.AnalyzerCompletionTracker;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import javax.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class KafkaStreamsTopologyTest extends PersistenceCapableTest {

    private Topology topology;
    private TopologyTestDriver testDriver;
    private TestInputTopic<UUID, MetaModel> repoMetaAnalysisResultInputTopic;
    private TestInputTopic<UUID, VulnerabilityResult> vulnAnalysisResultInputTopic;
    private TestInputTopic<UUID, AnalyzerConfig> analyzerConfigTopic;

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @Before
    public void setUp() {
        topology = new KafkaStreamsTopologyFactory().createTopology();

        testDriver = new TopologyTestDriver(topology);
        repoMetaAnalysisResultInputTopic = testDriver.createInputTopic(KafkaTopic.REPO_META_ANALYSIS_RESULT.getName(),
                new UUIDSerializer(), new JacksonSerializer<>());
        vulnAnalysisResultInputTopic = testDriver.createInputTopic(KafkaTopic.VULN_ANALYSIS_RESULT.getName(),
                new UUIDSerializer(), new JacksonSerializer<>());
        analyzerConfigTopic = testDriver.createInputTopic(KafkaTopic.VULN_ANALYSIS_INFO.getName(),
                new UUIDSerializer(), new JacksonSerializer<>());

        System.setOut(new PrintStream(outContent));
    }

    @After
    public void tearDown() {
        System.setOut(originalOut);
        testDriver.close();
    }


    @Test
    // FIXME: Currently failing b/c notifications are being dispatched via NotificationUtil, but no Kafka producer
    // is available. Will need to refactor NotificationUtil so that a MockProducer can be injected.
    public void testVulnResultIngestion() {

        AnalyzerConfig analyzerConfig = new AnalyzerConfig(true, true,true);
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        final var reportedVuln = new Vulnerability();
        reportedVuln.setVulnId("INT-123");
        reportedVuln.setSource(Vulnerability.Source.INTERNAL);

        final var reportedVuln2 = new Vulnerability();
        reportedVuln2.setVulnId("INT-124");
        reportedVuln2.setSource(Vulnerability.Source.INTERNAL);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(reportedVuln);
        vulnerabilities.add(reportedVuln2);

        final Date beforeAnalysis = new Date();
        vulnAnalysisResultInputTopic.pipeInput(component.getUuid(), new VulnerabilityResult(vulnerabilities, AnalyzerIdentity.INTERNAL_ANALYZER, false));

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getLastVulnerabilityAnalysis()).isAfter(beforeAnalysis);

        final List<Vulnerability> vulns = qm.getAllVulnerabilities(component);
        assertThat(vulns).hasSize(2);

        final Vulnerability vuln = vulns.get(0);
        assertThat(vuln.getVulnId()).isEqualTo("INT-123");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.INTERNAL.name());

        final FindingAttribution attribution = qm.getFindingAttribution(vuln, component);
        assertThat(attribution).isNotNull();
        assertThat(attribution.getAnalyzerIdentity()).isEqualTo(AnalyzerIdentity.INTERNAL_ANALYZER);
       }

    @Test
    public void testVulnCompletion(){
        AnalyzerConfig analyzerConfig = new AnalyzerConfig(true, true,true);
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        final var reportedVuln = new Vulnerability();
        reportedVuln.setVulnId("INT-123");
        reportedVuln.setSource(Vulnerability.Source.INTERNAL);

        final var reportedVuln2 = new Vulnerability();
        reportedVuln2.setVulnId("INT-124");
        reportedVuln2.setSource(Vulnerability.Source.INTERNAL);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(reportedVuln);
        vulnerabilities.add(reportedVuln2);

        analyzerConfigTopic.pipeInput(component.getUuid(), analyzerConfig);
        vulnAnalysisResultInputTopic.pipeInput(component.getUuid(), new VulnerabilityResult(vulnerabilities, AnalyzerIdentity.INTERNAL_ANALYZER, false));
        vulnAnalysisResultInputTopic.pipeInput(component.getUuid(), new VulnerabilityResult(vulnerabilities, AnalyzerIdentity.OSSINDEX_ANALYZER, false));

        assertThat(AnalyzerCompletionTracker.completionTrackMap.get(component.getUuid()).isInternalCompleted()).isEqualTo(true);
        assertThat(AnalyzerCompletionTracker.completionTrackMap.get(component.getUuid()).isOSSCompleted()).isEqualTo(true);
        Assert.assertFalse(outContent.toString().contains("completed"));

        vulnAnalysisResultInputTopic.pipeInput(component.getUuid(), new VulnerabilityResult(vulnerabilities, AnalyzerIdentity.SNYK_ANALYZER, false));
        assertThat(AnalyzerCompletionTracker.completionTrackMap.get(component.getUuid()).isSnykCompleted()).isEqualTo(true);
        Assert.assertTrue(outContent.toString().contains("completed"));
    }


    @Test
    public void testVulnResultIngestionNoFinding() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        final Date beforeAnalysis = new Date();
        vulnAnalysisResultInputTopic.pipeInput(component.getUuid(), new VulnerabilityResult(null, AnalyzerIdentity.INTERNAL_ANALYZER, false));

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getLastVulnerabilityAnalysis()).isAfter(beforeAnalysis);

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).isEmpty();
    }

    @Test
    public void testRepoMetaAnalysisResultIngestion() {
        final Date beforeTestTimestamp = Date.from(Instant.now());

        final var component = new Component();
        component.setPurl("pkg:golang/github.com/foo/bar@1.2.3");

        final var metaModel = new MetaModel(component);
        metaModel.setLatestVersion("1.2.4");

        repoMetaAnalysisResultInputTopic.pipeInput(UUID.randomUUID(), metaModel);

        final RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(RepositoryType.GO_MODULES, "github.com/foo", "bar");
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.GO_MODULES);
        assertThat(metaComponent.getNamespace()).isEqualTo("github.com/foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isNull();
        assertThat(metaComponent.getLastCheck()).isAfter(beforeTestTimestamp);
    }

    @Test
    public void testRepoMetaAnalysisResultNoResult() {
        final var component = new Component();
        component.setPurl("pkg:golang/github.com/foo/bar@1.2.3");

        final var metaModel = new MetaModel(component);

        repoMetaAnalysisResultInputTopic.pipeInput(UUID.randomUUID(), metaModel);

        final RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(RepositoryType.GO_MODULES, "github.com/foo", "bar");
        assertThat(metaComponent).isNull();
    }

    @Test
    @Ignore
    public void describe() {
        System.out.println(topology.describe().toString());
    }

}