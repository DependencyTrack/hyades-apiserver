package org.dependencytrack.event;

import org.dependencytrack.PersistenceCapableTest;
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

public class PurlMigratorTest extends PersistenceCapableTest {

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
        PurlMigrator initializer = new PurlMigrator(false);
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isZero();
        assertThat(kafkaMockProducer.history().size()).isZero();
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataProcessed() {
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        integrityMetaExisting.setStatus(PROCESSED);
        qm.persist(integrityMetaExisting);
        // data exists in IntegrityMetaComponent so sync will be skipped
        PurlMigrator initializer = new PurlMigrator(true);
        initializer.contextInitialized(null);
        // kafka event is not dispatched
        assertThat(kafkaMockProducer.history().size()).isZero();
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

        PurlMigrator initializer = new PurlMigrator(true);
        initializer.contextInitialized(null);
        // kafka event is dispatched
        assertThat(kafkaMockProducer.history().size()).isZero();
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }
}
