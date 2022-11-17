package org.dependencytrack.event.kafka;

import alpine.notification.Notification;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import org.apache.kafka.common.serialization.UUIDSerializer;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyTestDriver;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.dto.VulnerabilityResult;
import org.dependencytrack.event.kafka.serialization.JacksonSerializer;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;

public class KafkaStreamsTopologyTest extends PersistenceCapableTest {

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    private Topology topology;
    private TopologyTestDriver testDriver;
    private TestInputTopic<UUID, VulnerabilityResult> inputTopic;

    @BeforeClass
    public static void setUpClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
    }

    @AfterClass
    public static void tearDownClass() {
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
    }

    @Before
    public void setUp() {
        topology = new KafkaStreamsTopologyFactory().createTopology();

        testDriver = new TopologyTestDriver(topology);
        inputTopic = testDriver.createInputTopic(KafkaTopic.COMPONENT_VULNERABILITY_ANALYSIS_RESULT.getName(),
                new UUIDSerializer(), new JacksonSerializer<>());
    }

    @After
    public void tearDown() {
        NOTIFICATIONS.clear();
        testDriver.close();
    }

    @Test
    public void testVulnResultIngestion() throws InterruptedException {
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

        final Date beforeAnalysis = new Date();
        inputTopic.pipeInput(component.getUuid(), new VulnerabilityResult(reportedVuln, AnalyzerIdentity.INTERNAL_ANALYZER));

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() >= 1, Duration.ofSeconds(5));
        assertThat(NOTIFICATIONS).satisfiesExactly(
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITY.name())
        );

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getLastVulnerabilityAnalysis()).isAfter(beforeAnalysis);

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(1);

        final Vulnerability vuln = vulnerabilities.get(0);
        assertThat(vuln.getVulnId()).isEqualTo("INT-123");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.INTERNAL.name());

        final FindingAttribution attribution = qm.getFindingAttribution(vuln, component);
        assertThat(attribution).isNotNull();
        assertThat(attribution.getAnalyzerIdentity()).isEqualTo(AnalyzerIdentity.INTERNAL_ANALYZER);
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
        inputTopic.pipeInput(component.getUuid(), new VulnerabilityResult(null, AnalyzerIdentity.INTERNAL_ANALYZER));

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getLastVulnerabilityAnalysis()).isAfter(beforeAnalysis);

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).isEmpty();
    }

    @Test
    @Ignore
    public void describe() {
        System.out.println(topology.describe().toString());
    }

}