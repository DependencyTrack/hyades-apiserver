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

        assertThat(qm.getAllWorkflowStateById(result.getId())).satisfies(
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
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep("Step-1");
        workflowState.setStatus("PENDING");
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result = qm.persist(workflowState);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(result);
        workflowState2.setFailureReason(null);
        workflowState2.setStep("Step-2");
        workflowState2.setStatus("PENDING");
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState2);

        assertThat(qm.getAllWorkflowStatesForParentByToken(uuid, result)).satisfiesExactly(
                state -> {
                    assertThat(state.getStatus()).isEqualTo("PENDING");
                    assertThat(state.getStep()).isEqualTo("Step-2");
                    assertThat(state.getParent().getId()).isEqualTo(result.getId());
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
}
