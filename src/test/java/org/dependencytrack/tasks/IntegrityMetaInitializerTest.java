package org.dependencytrack.tasks;

import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.IntegrityMetaInitializer;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.FetchStatus.PROCESSED;

public class IntegrityMetaInitializerTest extends AbstractPostgresEnabledTest {

    @Test
    public void testIntegrityMetaInitializerWithNoData() {

        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer();
        // no existing data in IntegrityMetaComponent
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(0);
        assertThat(kafkaMockProducer.history().size()).isEqualTo(0);
    }

    @Test
    public void testIntegrityMetaInitializer() {

        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setInternal(false);
        componentProjectA.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        componentProjectA.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        qm.persist(componentProjectA);

        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer();
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
        assertThat(qm.getIntegrityMetaComponent(componentProjectA.getPurl().toString())).satisfies(
                meta -> {
                    assertThat(meta.getStatus()).isNull();
                    assertThat(meta.getPurl()).isEqualTo("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
                    assertThat(meta.getId()).isEqualTo(1L);
                    assertThat(meta.getMd5()).isNull();
                    assertThat(meta.getSha1()).isNull();
                    assertThat(meta.getSha256()).isNull();
                    assertThat(meta.getLastFetch()).isNull();
                    assertThat(meta.getPublishedAt()).isNull();
                }
        );
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name())
        );
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingData() {
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl("pkg:npm/acme/acme-lib-c@3.0.1");
        integrityMetaExisting.setStatus(PROCESSED);
        qm.persist(integrityMetaExisting);
        // data exists in IntegrityMetaComponent so sync will be skipped
        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer();
        initializer.contextInitialized(null);
        assertThat(kafkaMockProducer.history().size()).isEqualTo(0);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }
}
