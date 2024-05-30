package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.CloneProjectEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.resources.v1.vo.CloneProjectRequest;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStep.PROJECT_CLONE;

public class CloneProjectTaskTest extends PersistenceCapableTest {

    @Test
    public void testCloneProjectTask() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        CloneProjectRequest request = new CloneProjectRequest(project.getUuid().toString(), "1.1", false, false, false, false, false, false, false);
        final var cloneProjectEvent = new CloneProjectEvent(request);
        new CloneProjectTask().inform(cloneProjectEvent);
        var clonedProject = qm.getProject("Acme Example", "1.1");
        assertThat(clonedProject).isNotNull();
        assertThat(qm.getAllWorkflowStatesForAToken(cloneProjectEvent.getChainIdentifier())).satisfiesExactly(
                state -> {
                    assertThat(state.getStep()).isEqualTo(PROJECT_CLONE);
                    assertThat(state.getStatus()).isEqualTo(COMPLETED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                });

    }
}
