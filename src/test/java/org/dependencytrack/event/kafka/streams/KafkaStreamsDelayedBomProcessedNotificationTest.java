package org.dependencytrack.event.kafka.streams;

import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.ReadKeyValues;
import net.mguenther.kafka.junit.SendKeyValues;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;
import org.dependencytrack.proto.vulnanalysis.v1.ScanResult;
import org.dependencytrack.proto.vulnanalysis.v1.ScannerResult;
import org.junit.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
import static org.dependencytrack.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_SUCCESSFUL;
import static org.dependencytrack.proto.vulnanalysis.v1.Scanner.SCANNER_INTERNAL;

public class KafkaStreamsDelayedBomProcessedNotificationTest extends KafkaStreamsTest {

    public KafkaStreamsDelayedBomProcessedNotificationTest() {
        super(new KafkaStreamsTopologyFactory(true)::createTopology);
    }

    @Test
    public void shouldSendBomProcessedNotification() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setDescription("Some Description");
        project.setPurl("pkg:maven/com.acme/acme-app");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("tag-a"),
                qm.createTag("tag-b")
        ));

        final var scanToken = UUID.randomUUID().toString();

        // Initialize a vulnerability scan for 5 components, and create a workflow for it accordingly.
        final VulnerabilityScan scan = qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, project.getUuid(), scanToken, 5);
        qm.createWorkflowSteps(UUID.fromString(scanToken));

        // Transition the BOM_PROCESSING step of the workflow to COMPLETED. A delayed BOM_PROCESSED notification
        // will only be sent, when there's a successful BOM_PROCESSING step in the workflow.
        final WorkflowState state = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scanToken), WorkflowStep.BOM_PROCESSING);
        state.setStatus(WorkflowStatus.COMPLETED);
        qm.updateWorkflowState(state);

        // Emulate arrival of 5 vulnerability scan results, one for each component in the project.
        final var componentUuids = new ArrayList<UUID>();
        for (int i = 0; i < 5; i++) {
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
                                            .build()))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        }

        // Wait for vulnerability scan to transition to COMPLETED status.
        await("Result processing")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    qm.getPersistenceManager().refresh(scan);
                    assertThat(scan).isNotNull();
                    assertThat(scan.getStatus()).isEqualTo(VulnerabilityScan.Status.COMPLETED);
                });

        await("BOM processed notification")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    assertThat(kafka.readValues(ReadKeyValues
                            .from(KafkaTopics.NOTIFICATION_BOM.name(), String.class, Notification.class)
                            .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                            .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class))
                    ).satisfiesExactly(
                            notification -> {
                                final BomConsumedOrProcessedSubject subject =
                                        notification.getSubject().unpack(BomConsumedOrProcessedSubject.class);
                                assertThat(subject.getBom().getContent()).isEqualTo("(Omitted)");
                                assertThat(subject.getBom().getFormat()).isEqualTo("CycloneDX");
                                assertThat(subject.getBom().getSpecVersion()).isEqualTo("Unknown");
                                assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
                                assertThat(subject.getProject().getName()).isEqualTo(project.getName());
                                assertThat(subject.getProject().getVersion()).isEqualTo(project.getVersion());
                                assertThat(subject.getProject().getDescription()).isEqualTo(project.getDescription());
                                assertThat(subject.getProject().getPurl()).isEqualTo(project.getPurl().toString());
                                assertThat(subject.getProject().getTagsList()).containsExactlyInAnyOrder("tag-a", "tag-b");
                            }
                    );
                });

        // ... we still want to get a PROJECT_VULN_ANALYSIS_COMPLETE notification though.
        // In this case, no vulnerabilities were found, so no findings are expected.
        await("Analysis complete notification")
                .atMost(Duration.ofSeconds(15))
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
                                assertThat(subject.getFindingsList()).isEmpty();
                            }
                    );
                });
    }

    @Test
    public void shouldNotSendBomProcessedNotificationWhenWorkflowHasNoCompletedBomProcessingStep() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var scanToken = UUID.randomUUID().toString();

        // Initialize a vulnerability scan for 5 components, and create a workflow for a manual re-analysis.
        // This workflow does not include a BOM_PROCESSING step. Without it, no BOM_PROCESSED notification should be sent.
        final VulnerabilityScan scan = qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, project.getUuid(), scanToken, 5);
        qm.createReanalyzeSteps(UUID.fromString(scanToken));

        // Emulate arrival of 5 vulnerability scan results, one for each component in the project.
        final var componentUuids = new ArrayList<UUID>();
        for (int i = 0; i < 5; i++) {
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
                                            .build()))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        }

        // Wait for vulnerability scan to transition to COMPLETED status.
        await("Result processing")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    qm.getPersistenceManager().refresh(scan);
                    assertThat(scan).isNotNull();
                    assertThat(scan.getStatus()).isEqualTo(VulnerabilityScan.Status.COMPLETED);
                });

        // We still want to get a PROJECT_VULN_ANALYSIS_COMPLETE notification though.
        // In this case, no vulnerabilities were found, so no findings are expected.
        await("Analysis complete notification")
                .atMost(Duration.ofSeconds(15))
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
                                assertThat(subject.getFindingsList()).isEmpty();
                            }
                    );
                });

        // No BOM_PROCESSED notification should've been sent.
        assertThat(kafka.readValues(ReadKeyValues
                .from(KafkaTopics.NOTIFICATION_BOM.name(), String.class, Notification.class)
                .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class))
        ).isEmpty();
    }

    @Test
    public void shouldNotSendBomProcessedNotificationWhenProjectDoesNotExistAnymore() throws Exception {
        // Instead of creating a project, just generate a random project UUID.
        // Internally, vulnerability analysis should still complete, but no notification should be sent.
        final var projectUuid = UUID.randomUUID();

        final var scanToken = UUID.randomUUID().toString();

        // Initialize a vulnerability scan for 5 components, and create a workflow for it accordingly.
        final VulnerabilityScan scan = qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, projectUuid, scanToken, 5);
        qm.createWorkflowSteps(UUID.fromString(scanToken));

        // Transition the BOM_PROCESSING step of the workflow to COMPLETED. A delayed BOM_PROCESSED notification
        // will only be sent, when there's a successful BOM_PROCESSING step in the workflow.
        final WorkflowState state = qm.getWorkflowStateByTokenAndStep(UUID.fromString(scanToken), WorkflowStep.BOM_PROCESSING);
        state.setStatus(WorkflowStatus.COMPLETED);
        qm.updateWorkflowState(state);

        // Emulate arrival of 5 vulnerability scan results, one for each component in the project.
        final var componentUuids = new ArrayList<UUID>();
        for (int i = 0; i < 5; i++) {
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
                                            .build()))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        }

        // Wait for vulnerability scan to transition to COMPLETED status.
        await("Result processing")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    qm.getPersistenceManager().refresh(scan);
                    assertThat(scan).isNotNull();
                    assertThat(scan.getStatus()).isEqualTo(VulnerabilityScan.Status.COMPLETED);
                });

        // No PROJECT_VULN_ANALYSIS_COMPLETE notification should've been sent.
        assertThat(kafka.readValues(ReadKeyValues
                .from(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), String.class, Notification.class)
                .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class))
        ).isEmpty();

        // No BOM_PROCESSED notification should've been sent.
        assertThat(kafka.readValues(ReadKeyValues
                .from(KafkaTopics.NOTIFICATION_BOM.name(), String.class, Notification.class)
                .with(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                .with(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, NotificationDeserializer.class))
        ).isEmpty();
    }

}
