package org.dependencytrack.event.kafka;

import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.SendKeyValues;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.VulnerabilityScan;
import org.hyades.proto.repometaanalysis.v1.AnalysisResult;
import org.hyades.proto.vuln.v1.Source;
import org.hyades.proto.vulnanalysis.v1.Component;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;
import org.junit.Ignore;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.hyades.proto.vuln.v1.Source.SOURCE_OSSINDEX;
import static org.hyades.proto.vuln.v1.Source.SOURCE_SNYK;
import static org.hyades.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_COMPLETE;
import static org.hyades.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_SUCCESSFUL;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_INTERNAL;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_NONE;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_OSSINDEX;
import static org.hyades.proto.vulnanalysis.v1.Scanner.SCANNER_SNYK;

public class KafkaStreamsTopologyTest extends KafkaStreamsTest {

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
                                        .setScanner(SCANNER_SNYK)
                                        .setStatus(SCAN_STATUS_SUCCESSFUL)
                                        .addVulnerabilities(vulnComponentA)
                                        .build()),
                        new KeyValue<>(scanKeyComponentB,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentB)
                                        .setScanner(SCANNER_OSSINDEX)
                                        .setStatus(SCAN_STATUS_SUCCESSFUL)
                                        .addVulnerabilities(vulnComponentB)
                                        .build())))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));

        assertConditionWithTimeout(() -> !qm.getAllVulnerabilities(componentA).isEmpty()
                && !qm.getAllVulnerabilities(componentB).isEmpty(), Duration.ofSeconds(5));
    }

    @Test
    public void vulnScanCompletionTest() throws Exception {
        final var scanToken = UUID.randomUUID().toString();

        final VulnerabilityScan scan = qm.createVulnerabilityScan(scanToken, 500);

        final var componentUuids = new ArrayList<UUID>();
        for (int i = 0; i < 500; i++) {
            componentUuids.add(UUID.randomUUID());
        }

        for (final UUID uuid : componentUuids) {
            kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_COMMAND.name(), List.of(
                            new KeyValue<>(
                                    ScanKey.newBuilder()
                                            .setScanToken(scanToken)
                                            .setComponentUuid(uuid.toString())
                                            .build(),
                                    ScanCommand.newBuilder()
                                            .setComponent(Component.newBuilder()
                                                    .setUuid(uuid.toString())
                                                    .build())
                                            .build()
                            ))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
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
                                            .setScanner(SCANNER_NONE)
                                            .setStatus(SCAN_STATUS_COMPLETE)
                                            .build()))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        }

        assertConditionWithTimeout(() -> {
            qm.getPersistenceManager().refresh(scan);
            return scan != null && scan.getReceivedResults() == 500;
        }, Duration.ofSeconds(15));

        assertThat(scan.getToken()).isEqualTo(scanToken);
        assertThat(scan.getExpectedResults()).isEqualTo(500);
        assertThat(scan.getReceivedResults()).isEqualTo(500);
        assertThat(scan.getStatus()).isEqualTo(VulnerabilityScan.Status.COMPLETED);
        assertThat(scan.getUpdatedAt()).isAfter(scan.getStartedAt());
    }

}
