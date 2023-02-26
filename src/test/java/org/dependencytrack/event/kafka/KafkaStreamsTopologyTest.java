package org.dependencytrack.event.kafka;

import net.mguenther.kafka.junit.KeyValue;
import net.mguenther.kafka.junit.SendKeyValues;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.UUIDSerializer;
import org.apache.kafka.streams.StoreQueryParameters;
import org.apache.kafka.streams.state.QueryableStoreTypes;
import org.apache.kafka.streams.state.ReadOnlyKeyValueStore;
import org.dependencytrack.event.kafka.serialization.JacksonSerializer;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.MetaModel;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.hyades.proto.vuln.v1.Source;
import org.hyades.proto.vulnanalysis.v1.Component;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;
import org.hyades.proto.vulnanalysis.v1.ScanStatus;
import org.hyades.proto.vulnanalysis.v1.Scanner;
import org.hyades.proto.vulnanalysis.v1.internal.ScanCompletion;
import org.hyades.proto.vulnanalysis.v1.internal.ScanCompletionStatus;
import org.junit.Assert;
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

        final var component = new org.dependencytrack.model.Component();
        component.setUuid(UUID.randomUUID());
        component.setPurl("pkg:golang/github.com/foo/bar@1.2.3");

        final var metaModel = new MetaModel(component);
        metaModel.setLatestVersion("1.2.4");

        kafka.send(SendKeyValues.to(KafkaTopics.REPO_META_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(component.getUuid(), metaModel)
                ))
                .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, UUIDSerializer.class)
                .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JacksonSerializer.class));

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
                .setCorrelationId(scanToken.toString())
                .setComponentUuid(componentA.getUuid().toString())
                .build();
        final var scanKeyComponentB = ScanKey.newBuilder()
                .setCorrelationId(scanToken.toString())
                .setComponentUuid(componentB.getUuid().toString())
                .build();
        final var vulnComponentA = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("INT-001")
                .setSource(Source.SOURCE_INTERNAL)
                .build();
        final var vulnComponentB = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SONATYPE-001")
                .setSource(Source.SOURCE_OSSINDEX)
                .build();

        kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                        new KeyValue<>(scanKeyComponentA,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentA)
                                        .setScanner(Scanner.SCANNER_INTERNAL)
                                        .setStatus(ScanStatus.SCAN_STATUS_SUCCESSFUL)
                                        .addVulnerabilities(vulnComponentA)
                                        .build()),
                        new KeyValue<>(scanKeyComponentB,
                                ScanResult.newBuilder()
                                        .setKey(scanKeyComponentB)
                                        .setScanner(Scanner.SCANNER_OSSINDEX)
                                        .setStatus(ScanStatus.SCAN_STATUS_SUCCESSFUL)
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

        final var componentUuids = new ArrayList<UUID>();
        for (int i = 0; i < 500; i++) {
            componentUuids.add(UUID.randomUUID());
        }

        for (final UUID uuid : componentUuids) {
            kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_COMMAND.name(), List.of(
                            new KeyValue<>(
                                    ScanKey.newBuilder()
                                            .setCorrelationId(scanToken)
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
                    .setCorrelationId(scanToken)
                    .setComponentUuid(uuid.toString())
                    .build();

            kafka.send(SendKeyValues.to(KafkaTopics.VULN_ANALYSIS_RESULT.name(), List.of(
                            new KeyValue<>(
                                    scanKey,
                                    ScanResult.newBuilder()
                                            .setKey(scanKey)
                                            .setScanner(Scanner.SCANNER_NONE)
                                            .setStatus(ScanStatus.SCAN_STATUS_COMPLETE)
                                            .build()))
                    )
                    .with(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class)
                    .with(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class));
        }

        final ReadOnlyKeyValueStore<String, ScanCompletion> statusStore = kafkaStreams.store(StoreQueryParameters
                .fromNameAndType(KafkaStateStoreNames.VULNERABILITY_SCAN_COMPLETION, QueryableStoreTypes.keyValueStore()));

        try {
            assertConditionWithTimeout(() -> {
                final ScanCompletion completion = statusStore.get(scanToken);
                return completion != null && completion.getStatus() == ScanCompletionStatus.SCAN_COMPLETION_STATUS_COMPLETE;
            }, Duration.ofSeconds(5));
        } catch (AssertionError e) {
            final ReadOnlyKeyValueStore<String, Long> expectedStore = kafkaStreams.store(StoreQueryParameters
                    .fromNameAndType(KafkaStateStoreNames.EXPECTED_VULNERABILITY_SCAN_RESULTS, QueryableStoreTypes.keyValueStore()));
            final ReadOnlyKeyValueStore<String, Long> receivedStore = kafkaStreams.store(StoreQueryParameters
                    .fromNameAndType(KafkaStateStoreNames.RECEIVED_VULNERABILITY_SCAN_RESULTS, QueryableStoreTypes.keyValueStore()));
            final Long expected = expectedStore.get(scanToken);
            final Long received = receivedStore.get(scanToken);
            Assert.fail("Vulnerability scan was not marked as completed (expected: %d; received: %d)".formatted(expected, received));
        }
    }

}
