package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.IntegrityMetaInitializer;
import org.dependencytrack.model.Component;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrityMetaInitializerTest extends PersistenceCapableTest {

    @Test
    public void testIntegrityMetaInitializer() {

        IntegrityMetaInitializer initializer = new IntegrityMetaInitializer();

        // no existing data in IntegrityMetaComponent
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(0);

        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");

        qm.persist(componentProjectA);

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

        // data now exists in IntegrityMetaComponent so sync will be skipped
        final var componentProjectB = new Component();
        componentProjectB.setProject(projectA);
        componentProjectB.setName("acme-lib-b");
        componentProjectA.setPurl("pkg:maven/acme/acme-lib-c@3.0.1?foo=bar");
        qm.persist(componentProjectB);
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }
}
