package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Project;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrityMetaQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testGetIntegrityMetaComponent() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.TIMED_OUT);

        var result = qm.getIntegrityMetaComponent("pkg:maven/acme/example@1.0.0?type=jar");
        assertThat(result).isNull();

        result = qm.persist(integrityMeta);
        assertThat(qm.getIntegrityMetaComponent(result.getPurl())).satisfies(
                meta -> {
                    assertThat(meta.getStatus()).isEqualTo(FetchStatus.TIMED_OUT);
                    assertThat(meta.getId()).isEqualTo(1L);
                    assertThat(meta.getMd5()).isNull();
                    assertThat(meta.getSha1()).isNull();
                    assertThat(meta.getSha256()).isNull();
                    assertThat(meta.getLastFetch()).isNull();
                    assertThat(meta.getPublishedAt()).isNull();
                }
        );
    }

    @Test
    public void testUpdateIntegrityMetaComponent() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.TIMED_OUT);

        var result  = qm.updateIntegrityMetaComponent(integrityMeta);
        assertThat(result).isNull();

        var persisted = qm.persist(integrityMeta);
        persisted.setStatus(FetchStatus.PROCESSED);
        result  = qm.updateIntegrityMetaComponent(persisted);
        assertThat(result.getStatus()).isEqualTo(FetchStatus.PROCESSED);
    }

    @Test
    public void testSynchronizeIntegrityMetaComponent() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        component.setName("acme-lib");

        // without any component in database
        qm.synchronizeIntegrityMetaComponent();
        assertThat(qm.getIntegrityMetaComponent(component.getPurl().toString())).isNull();

        // with existing component in database
        qm.persist(component);
        qm.synchronizeIntegrityMetaComponent();
        assertThat(qm.getIntegrityMetaComponent(component.getPurl().toString())).satisfies(
                meta -> {
                    assertThat(meta.getStatus()).isNull();
                    assertThat(meta.getPurl()).isEqualTo("pkg:maven/acme/example@1.0.0?type=jar");
                    assertThat(meta.getId()).isEqualTo(1L);
                    assertThat(meta.getMd5()).isNull();
                    assertThat(meta.getSha1()).isNull();
                    assertThat(meta.getSha256()).isNull();
                    assertThat(meta.getLastFetch()).isNull();
                    assertThat(meta.getPublishedAt()).isNull();
                }
        );
    }

    @Test
    public void testGetIntegrityMetaComponentCount() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.TIMED_OUT);
        qm.persist(integrityMeta);

        integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:npm/acme/example@2.0.0");
        integrityMeta.setStatus(FetchStatus.PROCESSED);
        qm.persist(integrityMeta);

        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(2);
    }
}
