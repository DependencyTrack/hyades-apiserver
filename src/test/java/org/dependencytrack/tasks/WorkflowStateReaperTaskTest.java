package org.dependencytrack.tasks;

import alpine.Config;
import alpine.server.persistence.PersistenceManagerFactory;
import alpine.server.util.DbUtil;
import org.apache.commons.io.IOUtils;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.TestUtil;
import org.dependencytrack.event.WorkflowStateReaperEvent;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.persistence.QueryManager;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import javax.jdo.JDOObjectNotFoundException;
import javax.jdo.datastore.JDOConnection;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class WorkflowStateReaperTaskTest {

    private PostgreSQLContainer<?> postgresContainer;
    private QueryManager qm;

    @BeforeClass
    public static void init() {
        Config.enableUnitTests();
    }

    @Before
    public void setUp() throws Exception {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"))
                .withUsername("dtrack")
                .withPassword("dtrack")
                .withDatabaseName("dtrack");
        postgresContainer.start();

        final var dnProps = TestUtil.getDatanucleusProperties(postgresContainer.getJdbcUrl(),
                postgresContainer.getDriverClassName(),
                postgresContainer.getUsername(),
                postgresContainer.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

        qm = new QueryManager();

        final String shedlockSql = IOUtils.resourceToString("/shedlock.sql", StandardCharsets.UTF_8);
        final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
        final Connection connection = (Connection) jdoConnection.getNativeConnection();
        DbUtil.executeUpdate(connection, shedlockSql);
        jdoConnection.close();
    }

    @After
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void testTransitionToTimedOut() {
        final var token = UUID.randomUUID();

        final var parentState = new WorkflowState();
        parentState.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentState.setStatus(WorkflowStatus.PENDING);
        parentState.setToken(token);
        parentState.setStartedAt(Date.from(Instant.now().minus(12, ChronoUnit.HOURS)));
        parentState.setUpdatedAt(Date.from(Instant.now().minus(12, ChronoUnit.HOURS)));
        qm.persist(parentState);

        final var childState = new WorkflowState();
        childState.setParent(parentState);
        childState.setStep(WorkflowStep.BOM_PROCESSING);
        childState.setStatus(WorkflowStatus.PENDING);
        childState.setToken(token);
        qm.persist(childState);

        new WorkflowStateReaperTask(Duration.ofHours(6)).inform(new WorkflowStateReaperEvent());

        qm.getPersistenceManager().refreshAll(parentState, childState);
        assertThat(parentState.getStatus()).isEqualTo(WorkflowStatus.TIMED_OUT);
        assertThat(childState.getStatus()).isEqualTo(WorkflowStatus.PENDING);
    }

    @Test
    public void testTransitionTimedOutToFailed() {
        final var token = UUID.randomUUID();

        final var parentState = new WorkflowState();
        parentState.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentState.setStatus(WorkflowStatus.TIMED_OUT);
        parentState.setToken(token);
        parentState.setStartedAt(Date.from(Instant.now().minus(12, ChronoUnit.HOURS)));
        parentState.setUpdatedAt(Date.from(Instant.now().minus(12, ChronoUnit.HOURS)));
        qm.persist(parentState);

        final var childState = new WorkflowState();
        childState.setParent(parentState);
        childState.setStep(WorkflowStep.BOM_PROCESSING);
        childState.setStatus(WorkflowStatus.PENDING);
        childState.setToken(token);
        qm.persist(childState);

        new WorkflowStateReaperTask(Duration.ofHours(6)).inform(new WorkflowStateReaperEvent());

        qm.getPersistenceManager().refreshAll(parentState, childState);
        assertThat(parentState.getStatus()).isEqualTo(WorkflowStatus.FAILED);
        assertThat(parentState.getFailureReason()).isEqualTo("Timed out");
        assertThat(childState.getStatus()).isEqualTo(WorkflowStatus.CANCELLED);
        assertThat(childState.getFailureReason()).isNull();
    }

    @Test
    public void testDeleteExpiredWorkflows() {
        final var token = UUID.randomUUID();

        final var parentState = new WorkflowState();
        parentState.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentState.setStatus(WorkflowStatus.FAILED);
        parentState.setToken(token);
        parentState.setStartedAt(Date.from(Instant.now().minus(12, ChronoUnit.HOURS)));
        parentState.setUpdatedAt(Date.from(Instant.now().minus(12, ChronoUnit.HOURS)));
        qm.persist(parentState);

        final var childState = new WorkflowState();
        childState.setParent(parentState);
        childState.setStep(WorkflowStep.BOM_PROCESSING);
        childState.setStatus(WorkflowStatus.CANCELLED);
        childState.setToken(token);
        childState.setUpdatedAt(Date.from(Instant.now().minus(12, ChronoUnit.HOURS)));
        qm.persist(childState);

        new WorkflowStateReaperTask(Duration.ofHours(6)).inform(new WorkflowStateReaperEvent());

        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(WorkflowState.class, childState.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(WorkflowState.class, parentState.getId()));
    }

}