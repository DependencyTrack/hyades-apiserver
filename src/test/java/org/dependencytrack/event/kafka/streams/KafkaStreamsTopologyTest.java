/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.event.kafka.streams;

import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.event.framework.Subscriber;
import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.ReadKeyValues;
import net.mguenther.kafka.junit.SendKeyValues;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.TopologyDescription;
import org.assertj.core.api.SoftAssertions;
import org.cyclonedx.proto.v1_4.Bom;
import org.cyclonedx.proto.v1_4.Source;
import org.cyclonedx.proto.v1_4.VulnerabilityRating;
import org.dependencytrack.event.PortfolioVulnerabilityAnalysisEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.VulnerabilityScan.TargetType;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;
import org.dependencytrack.proto.vulnanalysis.v1.ScanResult;
import org.dependencytrack.proto.vulnanalysis.v1.ScannerResult;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static java.util.stream.Collectors.joining;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.cyclonedx.proto.v1_4.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_FAILED;
import static org.dependencytrack.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_FAILED;
import static org.dependencytrack.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_SUCCESSFUL;
import static org.dependencytrack.proto.vulnanalysis.v1.Scanner.SCANNER_INTERNAL;
import static org.dependencytrack.proto.vulnanalysis.v1.Scanner.SCANNER_OSSINDEX;
import static org.dependencytrack.proto.vulnanalysis.v1.Scanner.SCANNER_SNYK;

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
    public void after() {
        super.after();
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
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
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
                .addRatings(VulnerabilityRating.newBuilder()
                        .setSource(Source.newBuilder().setName("SNYK").build())
                        .setMethod(SCORE_METHOD_CVSSV3)
                        .setScore(10.0)
                        .setVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
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
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    var workflowStatus = qm.getWorkflowStateByTokenAndStep(scanToken, WorkflowStep.VULN_ANALYSIS);
                    qm.getPersistenceManager().refresh(workflowStatus); // Ensure we're not getting stale values from L1 cache
                    assertThat(workflowStatus.getStatus()).isEqualTo(WorkflowStatus.COMPLETED);
                });

        await("Analysis complete notification")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    assertThat(kafka.readValues(ReadKeyValues
                            .from(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), String.class, Notification.class)
                            .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                            .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class)
                            .withMaxTotalPollTime(5, TimeUnit.SECONDS))
                    ).satisfiesExactly(
                            notification -> {
                                final ProjectVulnAnalysisCompleteSubject subject =
                                        notification.getSubject().unpack(ProjectVulnAnalysisCompleteSubject.class);
                                assertThat(subject.getStatus()).isEqualTo(PROJECT_VULN_ANALYSIS_STATUS_COMPLETED);
                                assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
                                assertThat(subject.getFindingsList()).satisfiesExactlyInAnyOrder(
                                        finding -> {
                                            assertThat(finding.getComponent().getUuid()).isEqualTo(componentA.getUuid().toString());
                                            assertThat(finding.getVulnerabilitiesCount()).isEqualTo(1);
                                            assertThat(finding.getVulnerabilities(0).getVulnId()).isEqualTo("SNYK-001");
                                            assertThat(finding.getVulnerabilities(0).getSource()).isEqualTo("SNYK");
                                            assertThat(finding.getVulnerabilities(0).getSeverity()).isEqualTo("CRITICAL");
                                            assertThat(finding.getVulnerabilities(0).getCvssV3()).isEqualTo(10.0);
                                        },
                                        finding -> {
                                            assertThat(finding.getComponent().getUuid()).isEqualTo(componentB.getUuid().toString());
                                            assertThat(finding.getVulnerabilitiesCount()).isEqualTo(1);
                                            assertThat(finding.getVulnerabilities(0).getVulnId()).isEqualTo("SONATYPE-001");
                                            assertThat(finding.getVulnerabilities(0).getSource()).isEqualTo("OSSINDEX");
                                        }
                                );
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
                .atMost(Duration.ofSeconds(30))
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
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(50))
                .untilAsserted(() -> {
                    assertThat(kafka.readValues(ReadKeyValues
                            .from(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), String.class, Notification.class)
                            .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                            .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class)
                            .withMaxTotalPollTime(5, TimeUnit.SECONDS))
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
    public void projectVulnAnalysisCompleteNotificationFailureTest() throws Exception {
        // Initiate a vulnerability scan, but do not create a corresponding project.
        // Scan and workflow completion should work just fine, but assembling a notification
        // for PROJECT_VULN_ANALYSIS_COMPLETE will fail.
        final var scanToken = UUID.randomUUID();
        final var scanKey = ScanKey.newBuilder()
                .setScanToken(scanToken.toString())
                .setComponentUuid(UUID.randomUUID().toString())
                .build();
        qm.createVulnerabilityScan(TargetType.PROJECT, UUID.randomUUID(), scanToken.toString(), 1);
        qm.createWorkflowSteps(scanToken);

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(scanKey,
                                ScanResult.newBuilder()
                                        .setKey(scanKey)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_SNYK)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .setBom(Bom.newBuilder().build())
                                                .build())
                                        .build())))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        await("Workflow completion")
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    var workflowStatus = qm.getWorkflowStateByTokenAndStep(scanToken, WorkflowStep.VULN_ANALYSIS);
                    qm.getPersistenceManager().refresh(workflowStatus); // Ensure we're not getting stale values from L1 cache
                    assertThat(workflowStatus.getStatus()).isEqualTo(WorkflowStatus.COMPLETED);
                });

        // Verify that no notification was sent.
        final List<Notification> notifications = kafka.readValues(ReadKeyValues
                .from(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), String.class, Notification.class)
                .with(ConsumerConfig.GROUP_ID_CONFIG, "foo")
                .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class)
                .withMaxTotalPollTime(5, TimeUnit.SECONDS));
        assertThat(notifications).isEmpty();

        // Ensure that Kafka Streams did not terminate due to project not existing.
        assertThat(kafkaStreams.state()).isEqualTo(KafkaStreams.State.RUNNING);
    }

    @Test
    public void portfolioVulnAnalysisNotTrackedTest() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.createProject(project, null, false);

        final var component = new org.dependencytrack.model.Component();
        component.setName("acme-lib-a");
        component.setVersion("1.1.0");
        component.setProject(project);
        component.setPurl("pkg:maven/org.acme/acme-lib-a@1.1.0");
        qm.persist(component);

        final UUID scanToken = PortfolioVulnerabilityAnalysisEvent.CHAIN_IDENTIFIER;
        final var scanKey = ScanKey.newBuilder()
                .setScanToken(scanToken.toString())
                .setComponentUuid(component.getUuid().toString())
                .build();

        // Create a VulnerabilityScan targeting a project, using the scan token dedicated to
        // portfolio analysis. This will never actually happen, but we do it here to be able to verify
        // that portfolio analysis results are indeed filtered out.
        final VulnerabilityScan scan = qm.createVulnerabilityScan(TargetType.PROJECT, project.getUuid(), scanToken.toString(), 1);

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(scanKey,
                                ScanResult.newBuilder()
                                        .setKey(scanKey)
                                        .addScannerResults(ScannerResult.newBuilder()
                                                .setScanner(SCANNER_SNYK)
                                                .setStatus(SCAN_STATUS_SUCCESSFUL)
                                                .setBom(Bom.newBuilder()
                                                        .addVulnerabilities(org.cyclonedx.proto.v1_4.Vulnerability.newBuilder()
                                                                .setId("SNYK-001")
                                                                .setSource(Source.newBuilder().setName("SNYK").build()))
                                                        .build())
                                                .build())
                                        .build())))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        // Vulnerability results must still be processed...
        await("Result processing")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> assertThat(qm.getAllVulnerabilities(component)).hasSize(1));

        // ... but scan completion must not be.
        qm.getPersistenceManager().refresh(scan);
        assertThat(scan.getReceivedResults()).isZero();
        assertThat(scan.getStatus()).isEqualTo(VulnerabilityScan.Status.IN_PROGRESS);
    }

}
