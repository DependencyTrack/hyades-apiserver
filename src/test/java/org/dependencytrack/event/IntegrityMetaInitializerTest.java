package org.dependencytrack.event;

import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.junit.Before;
import org.junit.Test;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.FetchStatus.IN_PROGRESS;
import static org.dependencytrack.model.FetchStatus.PROCESSED;

public class IntegrityMetaInitializerTest extends AbstractPostgresEnabledTest {

    final Component componentPersisted = new Component();

    @Before
    public void persistComponentData() {
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        componentPersisted.setProject(projectA);
        componentPersisted.setName("acme-lib-a");
        componentPersisted.setInternal(false);
        componentPersisted.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        componentPersisted.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        qm.persist(componentPersisted);
        kafkaMockProducer.clear();
    }

    @Test
    public void testIntegrityMetaInitializerWhenDisabledByDefault() {
        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer();
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isZero();
        assertThat(kafkaMockProducer.history().size()).isZero();
    }

    @Test
    public void testIntegrityMetaInitializer() {
        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer(true);
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name())
        );
        assertThat(qm.getIntegrityMetaComponent(componentPersisted.getPurl().toString())).satisfies(
                meta -> {
                    assertThat(meta.getStatus()).isEqualTo(IN_PROGRESS);
                    assertThat(meta.getPurl()).isEqualTo("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
                    assertThat(meta.getId()).isEqualTo(1L);
                    assertThat(meta.getMd5()).isNull();
                    assertThat(meta.getSha1()).isNull();
                    assertThat(meta.getSha256()).isNull();
                    assertThat(meta.getLastFetch()).isNotNull();
                    assertThat(meta.getPublishedAt()).isNull();
                }
        );
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataProcessed() {
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        integrityMetaExisting.setStatus(PROCESSED);
        qm.persist(integrityMetaExisting);
        // data exists in IntegrityMetaComponent so sync will be skipped
        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer(true);
        initializer.contextInitialized(null);
        // kafka event is not dispatched
        assertThat(kafkaMockProducer.history().size()).isZero();
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataNotProcessed() {
        // data exists in IntegrityMetaComponent but not processed yet
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        qm.persist(integrityMetaExisting);
        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer(true);
        initializer.contextInitialized(null);
        // kafka event is dispatched
        assertThat(kafkaMockProducer.history().size()).isEqualTo(1);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataFetchedNotRecently() {
        // data exists in IntegrityMetaComponent but last fetched 3 hours ago > 1 hour wait time
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        integrityMetaExisting.setStatus(IN_PROGRESS);
        integrityMetaExisting.setLastFetch(Date.from(Instant.now().minus(3, ChronoUnit.HOURS)));
        qm.persist(integrityMetaExisting);
        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer(true);
        initializer.contextInitialized(null);
        // kafka event is dispatched
        assertThat(kafkaMockProducer.history().size()).isEqualTo(1);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataFetchedRecently() {
        // data exists in IntegrityMetaComponent but last fetched 30 min ago < 1 hour wait time
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        integrityMetaExisting.setStatus(IN_PROGRESS);
        integrityMetaExisting.setLastFetch(Date.from(Instant.now().minus(30, ChronoUnit.MINUTES)));
        qm.persist(integrityMetaExisting);

        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer(true);
        initializer.contextInitialized(null);
        // kafka event is dispatched
        assertThat(kafkaMockProducer.history().size()).isZero();
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }
}
