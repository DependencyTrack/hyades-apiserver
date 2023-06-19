package org.dependencytrack.event.kafka;

import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.event.framework.Subscriber;
import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.SendKeyValues;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.VulnerabilityScan.TargetType;
import org.dependencytrack.notification.vo.Findings;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.util.NotificationUtil;
import org.hyades.proto.repometaanalysis.v1.AnalysisResult;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;
import org.hyades.proto.vulnanalysis.v1.ScannerResult;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.hyades.proto.vuln.v1.Source.SOURCE_OSSINDEX;
import static org.hyades.proto.vuln.v1.Source.SOURCE_SNYK;
import static org.hyades.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_SUCCESSFUL;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_INTERNAL;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_OSSINDEX;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_SNYK;

public class KafkaStreamsTopologyTest extends KafkaStreamsTest {

    public static class EventSubscriber implements Subscriber {

        @Override
        public void inform(final Event event) {
            EVENTS.add(event);
        }

    }

    private static final ConcurrentLinkedQueue<Event> EVENTS = new ConcurrentLinkedQueue<>();

    @BeforeClass
    public static void setUpClass() {
        EventService.getInstance().subscribe(ProjectPolicyEvaluationEvent.class, PolicyEvaluationTask.class);
        EventService.getInstance().subscribe(ProjectMetricsUpdateEvent.class, EventSubscriber.class);
    }

    @After
    public void tearDown() {
        super.tearDown();
        EVENTS.clear();
    }

    @AfterClass
    public static void tearDownClass() {
        EventService.getInstance().unsubscribe(PolicyEvaluationTask.class);
        EventService.getInstance().unsubscribe(EventSubscriber.class);
    }

    @Test
    @Ignore
    // Un-ignore and run this test manually to get the topology description.
    // The description can be visualized using https://zz85.github.io/kafka-streams-viz/
    public void topologyDescriptionTest() {
        System.out.println(new KafkaStreamsTopologyFactory().createTopology().describe().toString());
    }

    @Test
    public void repoMetaAnalysisResultProcessingTest() throws Exception {
        final Date beforeTestTimestamp = Date.from(Instant.now());

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:golang/github.com/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .build();

        kafka.send(SendKeyValues.to(KafkaTopics.REPO_META_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>("pkg:golang/github.com/foo/bar", result)
                ))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        final Supplier<RepositoryMetaComponent> repoMetaSupplier =
                () -> qm.getRepositoryMetaComponent(RepositoryType.GO_MODULES, "github.com/foo", "bar");
        assertConditionWithTimeout(() -> repoMetaSupplier.get() != null, Duration.ofSeconds(5));

        final RepositoryMetaComponent metaComponent = repoMetaSupplier.get();
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.GO_MODULES);
        assertThat(metaComponent.getNamespace()).isEqualTo("github.com/foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isNull();
        assertThat(metaComponent.getLastCheck()).isAfter(beforeTestTimestamp);
    }

    @Test
    public void vulnScanResultProcessingTest() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.createProject(project, null, false);

        final var componentA = new org.dependencytrack.model.Component();
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.1.0");
        componentA.setProject(project);
        qm.persist(componentA);

        final var componentB = new org.dependencytrack.model.Component();
        componentB.setName("acme-lib-b");
        componentB.setVersion("1.2.0");
        componentB.setProject(project);
        qm.persist(componentB);

        final var scanToken = UUID.randomUUID();
        final var scanKeyComponentA = ScanKey.newBuilder()
                .setScanToken(scanToken.toString())
                .setComponentUuid(componentA.getUuid().toString())
                .build();
        final var scanKeyComponentB = ScanKey.newBuilder()
                .setScanToken(scanToken.toString())
                .setComponentUuid(componentB.getUuid().toString())
                .build();
        final var vulnComponentA = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SNYK-001")
                .setSource(SOURCE_SNYK)
                .build();
        final var vulnComponentB = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SONATYPE-001")
                .setSource(SOURCE_OSSINDEX)
                .build();

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(scanKeyComponentA,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentA)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_SNYK)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .addVulnerabilities(vulnComponentA))
                                        .build()),
                        new KeyValue<>(scanKeyComponentB,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentB)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_OSSINDEX)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .addVulnerabilities(vulnComponentB))
                                        .build())))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    assertThat(qm.getAllVulnerabilities(componentA)).hasSize(1);
                    assertThat(qm.getAllVulnerabilities(componentB)).hasSize(1);
                });

    }

    @Test
    public void vulnScanCompletionTest() throws Exception {
        final var projectUuid = UUID.randomUUID();
        final var scanToken = UUID.randomUUID().toString();

        final VulnerabilityScan scan = qm.createVulnerabilityScan(TargetType.PROJECT, projectUuid, scanToken, 500);

        final var componentUuids = new ArrayList<UUID>();
        for (int i = 0; i < 500; i++) {
            componentUuids.add(UUID.randomUUID());
        }

        for (final UUID uuid : componentUuids) {
            final ScanKey scanKey = ScanKey.newBuilder()
                    .setScanToken(scanToken)
                    .setComponentUuid(uuid.toString())
                    .build();

            kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                            new KeyValue<>(
                                    scanKey,
                                    ScanResult.newBuilder()
                                            .setKey(scanKey)
                                            .addScannerResults(ScannerResult.newBuilder()
                                                    .setScanner(SCANNER_INTERNAL)
                                                    .setStatus(SCAN_STATUS_SUCCESSFUL))
                                            .addScannerResults(ScannerResult.newBuilder()
                                                    .setScanner(SCANNER_OSSINDEX)
                                                    .setStatus(SCAN_STATUS_SUCCESSFUL))
                                            .build()))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        }

        await()
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    qm.getPersistenceManager().refresh(scan);
                    assertThat(scan).isNotNull();
                    assertThat(scan.getReceivedResults()).isEqualTo(500);
                });

        assertThat(scan.getToken()).isEqualTo(scanToken);
        assertThat(scan.getTargetType()).isEqualTo(TargetType.PROJECT);
        assertThat(scan.getTargetIdentifier()).isEqualTo(projectUuid);
        assertThat(scan.getExpectedResults()).isEqualTo(500);
        assertThat(scan.getReceivedResults()).isEqualTo(500);
        assertThat(scan.getStatus()).isEqualTo(VulnerabilityScan.Status.COMPLETED);
        assertThat(scan.getUpdatedAt()).isAfter(scan.getStartedAt());
    }

    @Test
    public void projectPolicyEvaluationAfterCompletedVulnScanTest() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.createProject(project, null, false);

        final var componentA = new org.dependencytrack.model.Component();
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.1.0");
        componentA.setProject(project);
        componentA.setPurl("pkg:maven/org.acme/acme-lib-a@1.1.0");
        qm.persist(componentA);

        final var componentB = new org.dependencytrack.model.Component();
        componentB.setName("acme-lib-b");
        componentB.setVersion("1.2.0");
        componentB.setProject(project);
        qm.persist(componentB);

        final var scanToken = UUID.randomUUID().toString();
        final VulnerabilityScan scan = qm.createVulnerabilityScan(TargetType.PROJECT, project.getUuid(), scanToken, 2);
        final var scanKeyA = ScanKey.newBuilder()
                .setScanToken(scanToken)
                .setComponentUuid(componentA.getUuid().toString())
                .build();
        final var scanKeyB = ScanKey.newBuilder()
                .setScanToken(scanToken)
                .setComponentUuid(componentB.getUuid().toString())
                .build();

        final Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy,
                PolicyCondition.Subject.PACKAGE_URL,
                PolicyCondition.Operator.MATCHES,
                "pkg:maven/org.acme/acme-lib-a@1.1.0"
        );

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(
                                scanKeyA,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyA)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_OSSINDEX)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL))
                                        .build()))
                )
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        await("First scan result processing")
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    qm.getPersistenceManager().refresh(scan);
                    assertThat(scan).isNotNull();
                    assertThat(scan.getReceivedResults()).isEqualTo(1);
                });

        // Evaluation of componentA should raise a policy violation. But because the vulnerability
        // scan was targeting a project, evaluation of individual components should not be performed.
        assertThat(qm.getAllPolicyViolations(project)).isEmpty();

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(
                                scanKeyB,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyB)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_OSSINDEX)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL))
                                        .build()))
                )
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        await("Scan completion")
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    qm.getPersistenceManager().refresh(scan);
                    assertThat(scan).isNotNull();
                    assertThat(scan.getReceivedResults()).isEqualTo(2);
                });
        // Vulnerability scan of the project completed. Policy evaluation of all components should
        // have been performed, so we expect the violation for componentA to appear.
        final var finalProject = project;
        await("Policy evaluation")
                .atMost(Duration.ofSeconds(30))
                .untilAsserted(() -> assertThat(qm.getAllPolicyViolations(finalProject)).hasSize(1));

        // A project metrics update should have been executed AFTER policy evaluation.
        // It thus should include the newly discovered policy violation.
        await("Project metrics update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(EVENTS).hasSize(1));
    }

    @Test
    public void createListTest() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.createProject(project, null, false);

        final var componentA = new org.dependencytrack.model.Component();
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.1.0");
        componentA.setProject(project);
        componentA.setPurl("pkg:maven/org.acme/acme-lib-a@1.1.0");
        qm.persist(componentA);

        final var componentB = new org.dependencytrack.model.Component();
        componentB.setName("acme-lib-b");
        componentB.setVersion("1.2.0");
        componentB.setProject(project);
        qm.persist(componentB);
        final var scanToken = UUID.randomUUID();
        final var scanKeyComponentA = ScanKey.newBuilder()
                .setScanToken(scanToken.toString())
                .setComponentUuid(componentA.getUuid().toString())
                .build();
        final var scanKeyComponentB = ScanKey.newBuilder()
                .setScanToken(scanToken.toString())
                .setComponentUuid(componentB.getUuid().toString())
                .build();
        final var vulnComponentA = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SNYK-001")
                .setSource(SOURCE_SNYK)
                .build();
        final var vulnComponentB = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SONATYPE-001")
                .setSource(SOURCE_OSSINDEX)
                .build();

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(scanKeyComponentA,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentA)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_SNYK)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .addVulnerabilities(vulnComponentA))
                                        .build()),
                        new KeyValue<>(scanKeyComponentB,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentB)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_OSSINDEX)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .addVulnerabilities(vulnComponentB))
                                        .build())))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        await()
                .atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    assertThat(qm.getAllVulnerabilities(componentA)).hasSize(1);
                    assertThat(qm.getAllVulnerabilities(componentB)).hasSize(1);
                });
        ConcurrentHashMap<String, List<Vulnerability>> map = new ConcurrentHashMap<>();
        map.put(componentA.getUuid().toString(), qm.getAllVulnerabilities(componentA));
        map.put(componentB.getUuid().toString(), qm.getAllVulnerabilities(componentB));
        List<Findings> componentAnalysisCompleteList = NotificationUtil.createList(qm.getAllComponents(project), map);
        assertThat(componentAnalysisCompleteList.get(0).getComponent().getName().equals("acme-lib-a"));
        Assertions.assertEquals(1, componentAnalysisCompleteList.get(0).getVulnerabilityList().size());
        Assertions.assertEquals("SNYK", componentAnalysisCompleteList.get(0).getVulnerabilityList().get(0).getSource());
        Assertions.assertEquals("SNYK-001", componentAnalysisCompleteList.get(0).getVulnerabilityList().get(0).getVulnId());
        assertThat(componentAnalysisCompleteList.get(1).getComponent().getName().equals("acme-lib-b"));
        Assertions.assertEquals(1, componentAnalysisCompleteList.get(1).getVulnerabilityList().size());
        Assertions.assertEquals("OSSINDEX", componentAnalysisCompleteList.get(1).getVulnerabilityList().get(0).getSource());
        Assertions.assertEquals("SONATYPE-001", componentAnalysisCompleteList.get(1).getVulnerabilityList().get(0).getVulnId());
    }

}
