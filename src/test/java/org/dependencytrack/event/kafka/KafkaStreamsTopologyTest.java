package org.dependencytrack.event.kafka;

import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.event.framework.Subscriber;
import com.google.protobuf.Timestamp;
import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.ReadKeyValues;
import net.mguenther.kafka.junit.SendKeyValues;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.TopologyDescription;
import org.assertj.core.api.SoftAssertions;
import org.cyclonedx.proto.v1_4.Bom;
import org.cyclonedx.proto.v1_4.Source;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufDeserializer;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIntegrityAnalysis;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.VulnerabilityScan.TargetType;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.vo.ComponentVulnAnalysisComplete;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.util.NotificationUtil;
import org.hyades.proto.notification.v1.Notification;
import org.hyades.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.hyades.proto.repometaanalysis.v1.AnalysisResult;
import org.hyades.proto.repometaanalysis.v1.HashMatchStatus;
import org.hyades.proto.repometaanalysis.v1.IntegrityResult;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;
import org.hyades.proto.vulnanalysis.v1.ScannerResult;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import javax.jdo.JDODataStoreException;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Supplier;

import static java.util.stream.Collectors.joining;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.hyades.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
import static org.hyades.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_FAILED;
import static org.hyades.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_FAILED;
import static org.hyades.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_SUCCESSFUL;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_INTERNAL;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_OSSINDEX;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_SNYK;

public class KafkaStreamsTopologyTest extends KafkaStreamsPostgresTest {

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
    public void processorNodeNamingTest() {
        final TopologyDescription topologyDescription = new KafkaStreamsTopologyFactory().createTopology().describe();

        final var softAsserts = new SoftAssertions();
        for (final TopologyDescription.Subtopology subtopology : topologyDescription.subtopologies()) {
            for (final TopologyDescription.Node node : subtopology.nodes()) {
                softAsserts.assertThat(node.name())
                        .as("Processor node has an invalid name (subTopology %d; parents: %s; children: %s)", subtopology.id(),
                                node.predecessors().stream().map(TopologyDescription.Node::name).collect(joining(", ")),
                                node.successors().stream().map(TopologyDescription.Node::name).collect(joining(", "))
                        )
                        .matches("^[a-z-_.]+$");
            }
        }

        softAsserts.assertAll();
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
    public void repoIntegrityAnalysisResultProcessingTest() throws Exception {
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
        final Date beforeTestTimestamp = Date.from(Instant.now());
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


        kafka.send(SendKeyValues.to(KafkaTopics.INTEGRITY_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", result)
                ))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        final Supplier<ComponentIntegrityAnalysis> repoMetaSupplier =
                () -> {
                    PersistenceManager pm = qm.getPersistenceManager();
                    pm.newQuery(pm.newQuery(ComponentIntegrityAnalysis.class));
                    final Transaction trx = pm.currentTransaction();
                    try {
                        trx.begin();
                        final Query<ComponentIntegrityAnalysis> query = pm.newQuery(ComponentIntegrityAnalysis.class);
                        query.setFilter("repositoryIdentifier == :repository && component.id == :id && component.uuid == :uuid");
                        query.setParameters(
                                "testRepo",
                                1,
                                uuid
                        );
                        ComponentIntegrityAnalysis persistentIntegrityResult = query.executeUnique();
                        trx.commit();
                        return persistentIntegrityResult;
                    } catch (JDODataStoreException ex) {
                        throw ex;
                    }

                };
        assertConditionWithTimeout(() -> repoMetaSupplier.get() != null, Duration.ofSeconds(5));

        final ComponentIntegrityAnalysis componentIntegrityAnalysis = repoMetaSupplier.get();
        assertThat(componentIntegrityAnalysis).isNotNull();
        assertThat(componentIntegrityAnalysis.getRepositoryIdentifier()).isEqualTo("testRepo");
        assertThat(componentIntegrityAnalysis.getComponent().getId()).isEqualTo(1);
        assertThat(componentIntegrityAnalysis.getComponent().getUuid()).isEqualTo(uuid);
        assertThat(componentIntegrityAnalysis.isIntegrityCheckPassed()).isTrue();
        assertThat(componentIntegrityAnalysis.isMd5HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
        assertThat(componentIntegrityAnalysis.isSha1HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
        assertThat(componentIntegrityAnalysis.isSha256HashMatched()).isEqualTo(HashMatchStatus.HASH_MATCH_STATUS_PASS.toString());
    }

    @Test
    public void vulnScanResultProcessingTest() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

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
        final var vulnComponentA = org.cyclonedx.proto.v1_4.Vulnerability.newBuilder()
                .setId("SNYK-001")
                .setSource(Source.newBuilder().setName("SNYK").build())
                .build();
        final var vulnComponentB = org.cyclonedx.proto.v1_4.Vulnerability.newBuilder()
                .setId("SONATYPE-001")
                .setSource(Source.newBuilder().setName("OSSINDEX").build())
                .build();

        qm.createVulnerabilityScan(TargetType.PROJECT, project.getUuid(), scanToken.toString(), 2);
        qm.createWorkflowSteps(scanToken);
        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(scanKeyComponentA,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentA)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_SNYK)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .setBom(Bom.newBuilder().addVulnerabilities(vulnComponentA)).build())
                                        .build()),
                        new KeyValue<>(scanKeyComponentB,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentB)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_OSSINDEX)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .setBom(Bom.newBuilder().addVulnerabilities(vulnComponentB)).build())
                                        .build())))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        await("Result processing")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    assertThat(qm.getAllVulnerabilities(componentA)).hasSize(1);
                    assertThat(qm.getAllVulnerabilities(componentB)).hasSize(1);
                });

        await("Workflow completion")
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    var workflowStatus = qm.getWorkflowStateByTokenAndStep(scanToken, WorkflowStep.VULN_ANALYSIS);
                    assertThat(workflowStatus.getStatus()).isEqualTo(WorkflowStatus.COMPLETED);
                });

        await("Analysis complete notification")
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    assertThat(kafka.readValues(ReadKeyValues
                            .from(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), String.class, Notification.class)
                            .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                            .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class))
                    ).satisfiesExactly(
                            notification -> {
                                final ProjectVulnAnalysisCompleteSubject subject =
                                        notification.getSubject().unpack(ProjectVulnAnalysisCompleteSubject.class);
                                assertThat(subject.getStatus()).isEqualTo(PROJECT_VULN_ANALYSIS_STATUS_COMPLETED);
                                assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
                                assertThat(subject.getFindingsCount()).isEqualTo(2);
                            }
                    );
                });
    }

    @Test
    public void vulnScanCompletionTest() throws Exception {
        final var projectUuid = UUID.randomUUID();
        final var scanToken = UUID.randomUUID().toString();

        final VulnerabilityScan scan = qm.createVulnerabilityScan(TargetType.PROJECT, projectUuid, scanToken, 500);
        qm.createWorkflowSteps(UUID.fromString(scanToken));

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

        await("Result processing")
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

        var workflowStatus = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scanToken), WorkflowStep.VULN_ANALYSIS);
        assertThat(workflowStatus.getStatus()).isEqualTo(WorkflowStatus.COMPLETED);
    }

    @Test
    public void vulnScanFailureTest() throws Exception {
        final var project = new Project();
        project.setName("foo");
        qm.persist(project);

        final var projectUuid = project.getUuid();
        final var scanToken = UUID.randomUUID().toString();

        final VulnerabilityScan scan = qm.createVulnerabilityScan(TargetType.PROJECT, projectUuid, scanToken, 100);
        qm.createWorkflowSteps(UUID.fromString(scanToken));

        final var componentUuids = new ArrayList<UUID>();
        for (int i = 0; i < 100; i++) {
            componentUuids.add(UUID.randomUUID());
        }

        for (int i = 0; i < 100; i++) {
            var scanStatus = i < 6 ? SCAN_STATUS_FAILED : SCAN_STATUS_SUCCESSFUL;
            final ScanKey scanKey = ScanKey.newBuilder()
                    .setScanToken(scanToken)
                    .setComponentUuid(componentUuids.get(i).toString())
                    .build();
            kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                            new KeyValue<>(
                                    scanKey,
                                    ScanResult.newBuilder()
                                            .setKey(scanKey)
                                            .addScannerResults(ScannerResult.newBuilder()
                                                    .setScanner(SCANNER_INTERNAL)
                                                    .setStatus(scanStatus))
                                            .addScannerResults(ScannerResult.newBuilder()
                                                    .setScanner(SCANNER_OSSINDEX)
                                                    .setStatus(scanStatus))
                                            .build()))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        }

        await("Result processing")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    qm.getPersistenceManager().refresh(scan);
                    assertThat(scan).isNotNull();
                    assertThat(scan.getReceivedResults()).isEqualTo(100);
                });

        assertThat(scan.getToken()).isEqualTo(scanToken);
        assertThat(scan.getTargetType()).isEqualTo(TargetType.PROJECT);
        assertThat(scan.getTargetIdentifier()).isEqualTo(projectUuid);
        assertThat(scan.getExpectedResults()).isEqualTo(100);
        assertThat(scan.getReceivedResults()).isEqualTo(100);
        assertThat(scan.getStatus()).isEqualTo(VulnerabilityScan.Status.FAILED);
        assertThat(scan.getUpdatedAt()).isAfter(scan.getStartedAt());

        await("Workflow completion")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    var workflowStatus = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scanToken), WorkflowStep.VULN_ANALYSIS);
                    assertThat(workflowStatus.getStatus()).isEqualTo(WorkflowStatus.FAILED);
                    assertThat(workflowStatus.getFailureReason()).isEqualTo("Failure threshold of 0.05% exceeded: 0.06% of scans failed");

                    workflowStatus = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scanToken), WorkflowStep.POLICY_EVALUATION);
                    assertThat(workflowStatus.getStatus()).isEqualTo(WorkflowStatus.CANCELLED);

                    workflowStatus = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scanToken), WorkflowStep.METRICS_UPDATE);
                    assertThat(workflowStatus.getStatus()).isEqualTo(WorkflowStatus.CANCELLED);
                });

        await("Analysis complete notification")
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(50))
                .untilAsserted(() -> {
                    assertThat(kafka.readValues(ReadKeyValues
                            .from(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), String.class, Notification.class)
                            .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                            .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class))
                    ).satisfiesExactly(
                            notification -> {
                                final ProjectVulnAnalysisCompleteSubject subject =
                                        notification.getSubject().unpack(ProjectVulnAnalysisCompleteSubject.class);
                                assertThat(subject.getStatus()).isEqualTo(PROJECT_VULN_ANALYSIS_STATUS_FAILED);
                                assertThat(subject.getProject().getUuid()).isEqualTo(projectUuid.toString());
                                assertThat(subject.getFindingsCount()).isZero();
                            }
                    );
                });

        // Policy evaluation and metrics were cancelled,
        // so no such events should've been emitted.
        assertThat(EVENTS).isEmpty();
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

        qm.createWorkflowSteps(UUID.fromString(scanToken));

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
        final var vulnComponentA = org.cyclonedx.proto.v1_4.Vulnerability.newBuilder()
                .setId("SNYK-001")
                .setSource(Source.newBuilder().setName("SNYK").build())
                .build();
        final var vulnComponentB = org.cyclonedx.proto.v1_4.Vulnerability.newBuilder()
                .setId("SONATYPE-001")
                .setSource(Source.newBuilder().setName("OSSINDEX").build())
                .build();

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(scanKeyComponentA,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentA)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_SNYK)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .setBom(Bom.newBuilder().addVulnerabilities(vulnComponentA)).build())
                                        .build()),
                        new KeyValue<>(scanKeyComponentB,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentB)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_OSSINDEX)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .setBom(Bom.newBuilder().addVulnerabilities(vulnComponentB)).build())
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
        List<ComponentVulnAnalysisComplete> componentAnalysisCompleteList = NotificationUtil.createList(qm.getAllComponents(project), map);
        assertThat(componentAnalysisCompleteList.get(0).getComponent().getName()).isEqualTo("acme-lib-a");
        Assertions.assertEquals(1, componentAnalysisCompleteList.get(0).getVulnerabilityList().size());
        Assertions.assertEquals("SNYK", componentAnalysisCompleteList.get(0).getVulnerabilityList().get(0).getSource());
        Assertions.assertEquals("SNYK-001", componentAnalysisCompleteList.get(0).getVulnerabilityList().get(0).getVulnId());
        assertThat(componentAnalysisCompleteList.get(1).getComponent().getName()).isEqualTo("acme-lib-b");
        Assertions.assertEquals(1, componentAnalysisCompleteList.get(1).getVulnerabilityList().size());
        Assertions.assertEquals("OSSINDEX", componentAnalysisCompleteList.get(1).getVulnerabilityList().get(0).getSource());
        Assertions.assertEquals("SONATYPE-001", componentAnalysisCompleteList.get(1).getVulnerabilityList().get(0).getVulnId());
    }

    public static class NotificationDeserializer extends KafkaProtobufDeserializer<Notification> {

        public NotificationDeserializer() {
            super(Notification.parser());
        }
    }

}
