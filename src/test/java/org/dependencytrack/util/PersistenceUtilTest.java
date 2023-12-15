package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.util.PersistenceUtil.Diff;
import org.dependencytrack.util.PersistenceUtil.Differ;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.PersistenceManager;
import javax.jdo.Transaction;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class PersistenceUtilTest extends PersistenceCapableTest {

    private PersistenceManager pm;

    @Before
    public void setUp() {
        pm = qm.getPersistenceManager();
    }

    @Test
    public void testAssertPersistentTx() {
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();

            final var project = new Project();
            project.setName("foo");
            pm.makePersistent(project);

            assertThatNoException()
                    .isThrownBy(() -> assertPersistent(project, null));
        } finally {
            trx.rollback();
        }
    }

    @Test
    public void testAssertPersistentNonTx() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatNoException()
                .isThrownBy(() -> assertPersistent(project, null));
    }

    @Test
    public void testAssertPersistentWhenTransient() {
        final var project = new Project();
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> assertPersistent(project, null));
    }

    @Test
    public void testAssertPersistentWhenDetached() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> assertPersistent(pm.detachCopy(project), null));
    }

    @Test
    public void testAssertNonPersistentTx() {
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();

            final var project = new Project();
            project.setName("foo");
            pm.makePersistent(project);

            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> assertNonPersistent(project, null));
        } finally {
            trx.rollback();
        }
    }

    @Test
    public void testAssertNonPersistentNonTx() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> assertNonPersistent(project, null));
    }

    @Test
    public void testAssertNonPersistentWhenTransient() {
        final var project = new Project();
        assertThatNoException()
                .isThrownBy(() -> assertNonPersistent(project, null));
    }

    @Test
    public void testAssertNonPersistentWhenDetached() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatNoException()
                .isThrownBy(() -> assertNonPersistent(pm.detachCopy(project), null));
    }

    @Test
    public void testDifferWithChanges() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setVersion("1.0.0");
        projectA.setDescription("identicalDescription");

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        projectB.setVersion("2.0.0");
        projectB.setDescription("identicalDescription");

        final var differ = new Differ<>(projectA, projectB);
        assertThat(differ.applyIfChanged("name", Project::getName, projectB::setName)).isTrue();
        assertThat(differ.applyIfChanged("version", Project::getVersion, projectB::setVersion)).isTrue();
        assertThat(differ.applyIfChanged("description", Project::getDescription, projectB::setDescription)).isFalse();

        assertThat(differ.getDiffs()).containsOnly(
                Map.entry("name", new Diff("acme-app-a", "acme-app-b")),
                Map.entry("version", new Diff("1.0.0", "2.0.0"))
        );
    }

    @Test
    public void testDifferWithoutChanges() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setVersion("1.0.0");
        projectA.setDescription("identicalDescription");

        final var projectB = new Project();
        projectB.setName("acme-app-a");
        projectB.setVersion("1.0.0");
        projectB.setDescription("identicalDescription");

        final var differ = new Differ<>(projectA, projectB);
        assertThat(differ.applyIfChanged("name", Project::getName, projectB::setName)).isFalse();
        assertThat(differ.applyIfChanged("version", Project::getVersion, projectB::setVersion)).isFalse();
        assertThat(differ.applyIfChanged("description", Project::getDescription, projectB::setDescription)).isFalse();

        assertThat(differ.getDiffs()).isEmpty();
    }

}