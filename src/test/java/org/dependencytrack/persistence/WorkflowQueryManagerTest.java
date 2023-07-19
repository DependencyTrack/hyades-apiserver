package org.dependencytrack.persistence;

import alpine.server.persistence.PersistenceManagerFactory;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.TestUtil;
import org.dependencytrack.model.WorkflowState;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.CANCELLED;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;
import static org.dependencytrack.model.WorkflowStep.REPO_META_ANALYSIS;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class WorkflowQueryManagerTest  {
    private PostgreSQLContainer<?> postgresContainer;
    private QueryManager qm;
    @Before
    public void setUp() throws Exception {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"))
                .withUsername("dtrack")
                .withPassword("dtrack")
                .withDatabaseName("dtrack");
        postgresContainer.start();

        final var dnProps = TestUtil.getDatabaseProperties(postgresContainer.getJdbcUrl(),
                postgresContainer.getDriverClassName(),
                postgresContainer.getUsername(),
                postgresContainer.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

        qm = new QueryManager();
    }

    @After
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void testWorkflowStateIsCreated() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState);

        assertThat(qm.getAllWorkflowStatesForAToken(uuid)).satisfiesExactly(
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getParent()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testShouldNotReturnWorkflowStateIfTokenDoesNotMatch() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState);

        //get states by a new token
        assertThat(qm.getAllWorkflowStatesForAToken(UUID.randomUUID())).isEmpty();
    }

    @Test
    public void testShouldGetWorkflowStateById() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result = qm.persist(workflowState);

        assertThat(qm.getWorkflowStateById(result.getId())).satisfies(
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getParent()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testShouldGetWorkflowStateByTokenAndStep() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);

        WorkflowState result = qm.persist(workflowState);

        assertThat(qm.getWorkflowStateByTokenAndStep(uuid, BOM_CONSUMPTION)).isEqualTo(result);
    }

    @Test
    public void testGetWorkflowStatesHierarchically() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(PENDING);
        workflowState1.setToken(uuid);
        workflowState1.setStartedAt(Date.from(Instant.now()));
        workflowState1.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result1 = qm.persist(workflowState1);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(result1);
        workflowState2.setFailureReason(null);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(PENDING);
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result2 = qm.persist(workflowState2);

        WorkflowState workflowState3 = new WorkflowState();
        workflowState3.setParent(result2);
        workflowState3.setFailureReason(null);
        workflowState3.setStep(REPO_META_ANALYSIS);
        workflowState3.setStatus(PENDING);
        workflowState3.setToken(uuid);
        workflowState3.setStartedAt(Date.from(Instant.now()));
        workflowState3.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState3);

        assertThat(qm.getAllWorkflowStatesForParent(result1)).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(BOM_PROCESSING);
                    assertThat(state.getParent().getId()).isEqualTo(result1.getId());
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                },
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(REPO_META_ANALYSIS);
                    assertThat(state.getParent().getId()).isEqualTo(result2.getId());
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testUpdateWorkflowStatesOfAllDescendants() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(PENDING);
        workflowState1.setToken(uuid);
        workflowState1.setStartedAt(Date.from(Instant.now()));
        workflowState1.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result1 = qm.persist(workflowState1);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(result1);
        workflowState2.setFailureReason(null);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(PENDING);
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result2 = qm.persist(workflowState2);

        WorkflowState workflowState3 = new WorkflowState();
        workflowState3.setParent(result2);
        workflowState3.setFailureReason(null);
        workflowState3.setStep(REPO_META_ANALYSIS);
        workflowState3.setStatus(PENDING);
        workflowState3.setToken(uuid);
        workflowState3.setStartedAt(Date.from(Instant.now()));
        workflowState3.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState3);

        assertThat(qm.updateAllWorkflowStatesForParent(result1, CANCELLED)).isEqualTo(2);
    }

    @Test
    public void testThrowsExceptionIfParentWorkflowStateIdIsMissing() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(PENDING);
        workflowState1.setToken(uuid);
        WorkflowState result1 = qm.persist(workflowState1);

        result1.setId(0);
        assertThrows(IllegalArgumentException.class, () -> qm.getAllWorkflowStatesForParent(null));
        assertThrows(IllegalArgumentException.class, () -> qm.getAllWorkflowStatesForParent(result1));
    }

    @Test
    public void testWorkflowStateIsUpdated() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState persisted = qm.persist(workflowState);

        persisted.setStatus(CANCELLED);

        WorkflowState result  = qm.updateWorkflowState(persisted);
        assertThat(result.getStatus()).isEqualTo(CANCELLED);
    }

    @Test
    public void testWorkflowStateIsDeleted() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState persisted = qm.persist(workflowState);

        qm.deleteWorkflowState(persisted);
        assertThat(qm.getWorkflowStateById(persisted.getId())).isNull();
    }
}
