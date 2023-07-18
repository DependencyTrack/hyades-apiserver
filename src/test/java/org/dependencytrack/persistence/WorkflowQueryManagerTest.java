package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.WorkflowState;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class WorkflowQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testWorkflowStateIsCreated() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep("Step-1");
        workflowState.setStatus("PENDING");
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState);

        qm.getAllWorkflowStatesForAToken(uuid);
        assertThat(qm.getAllWorkflowStatesForAToken(uuid)).satisfiesExactly(
                state -> {
                    assertThat(state.getStatus()).isEqualTo("PENDING");
                    assertThat(state.getStep()).isEqualTo("Step-1");
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getParent()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testShouldGetWorkflowStateById() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep("Step-1");
        workflowState.setStatus("PENDING");
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result = qm.persist(workflowState);

        assertThat(qm.getWorkflowStateById(result.getId())).satisfies(
                state -> {
                    assertThat(state.getStatus()).isEqualTo("PENDING");
                    assertThat(state.getStep()).isEqualTo("Step-1");
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getParent()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void getWorkflowStatesHierarchically() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep("Step-1");
        workflowState1.setStatus("PENDING");
        workflowState1.setToken(uuid);
        workflowState1.setStartedAt(Date.from(Instant.now()));
        workflowState1.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result1 = qm.persist(workflowState1);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(result1);
        workflowState2.setFailureReason(null);
        workflowState2.setStep("Step-2");
        workflowState2.setStatus("PENDING");
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result2 = qm.persist(workflowState2);

        WorkflowState workflowState3 = new WorkflowState();
        workflowState3.setParent(result2);
        workflowState3.setFailureReason(null);
        workflowState3.setStep("Step-3");
        workflowState3.setStatus("PENDING");
        workflowState3.setToken(uuid);
        workflowState3.setStartedAt(Date.from(Instant.now()));
        workflowState3.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState3);

        assertThat(qm.getAllWorkflowStatesForParentByToken(uuid, result1)).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStatus()).isEqualTo("PENDING");
                    assertThat(state.getStep()).isEqualTo("Step-2");
                    assertThat(state.getParent().getId()).isEqualTo(result1.getId());
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                },
                state -> {
                    assertThat(state.getStatus()).isEqualTo("PENDING");
                    assertThat(state.getStep()).isEqualTo("Step-3");
                    assertThat(state.getParent().getId()).isEqualTo(result2.getId());
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testWorkflowStateIsUpdated() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep("Step-1");
        workflowState.setStatus("PENDING");
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState persisted = qm.persist(workflowState);

        persisted.setStatus("CANCELLED");

        WorkflowState result  = qm.updateWorkflowState(persisted);
        assertThat(result.getStatus()).isEqualTo("CANCELLED");
    }

    @Test
    public void testWorkflowStateIsDeleted() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep("Step-1");
        workflowState.setStatus("PENDING");
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState persisted = qm.persist(workflowState);


        qm.deleteWorkflowState(persisted);
        assertThat(qm.getWorkflowStateById(persisted.getId())).isNull();
    }
}
