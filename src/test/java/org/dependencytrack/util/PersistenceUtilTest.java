package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.PersistenceManager;
import javax.jdo.Transaction;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
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

}