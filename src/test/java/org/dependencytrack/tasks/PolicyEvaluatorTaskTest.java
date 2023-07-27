package org.dependencytrack.tasks;

import org.assertj.core.api.Assertions;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.util.List;

import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStep.POLICY_EVALUATION;

public class PolicyEvaluatorTaskTest extends AbstractPostgresEnabledTest {

    @Test
    public void testWorkflowStateIsCompletedForComponent() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        var componentPolicyEvaluationEvent = new ComponentPolicyEvaluationEvent(component.getUuid());
        qm.createWorkflowSteps(componentPolicyEvaluationEvent.getChainIdentifier());
        new PolicyEvaluationTask().inform(componentPolicyEvaluationEvent);

        Assertions.assertThat(qm.getWorkflowStateByTokenAndStep(componentPolicyEvaluationEvent.getChainIdentifier(), POLICY_EVALUATION)).satisfies(
                state -> {
                    Assertions.assertThat(state.getStartedAt()).isNotNull();
                    Assertions.assertThat(state.getUpdatedAt()).isNotNull();
                    Assertions.assertThat(state.getStatus()).isEqualTo(COMPLETED);
                }
        );
    }

    @Test
    public void testWorkflowStateIsCompletedForProject() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        var projectPolicyEvaluationTaskEvent = new ProjectPolicyEvaluationEvent(component.getUuid());
        qm.createWorkflowSteps(projectPolicyEvaluationTaskEvent.getChainIdentifier());
        new PolicyEvaluationTask().inform(projectPolicyEvaluationTaskEvent);

        Assertions.assertThat(qm.getWorkflowStateByTokenAndStep(projectPolicyEvaluationTaskEvent.getChainIdentifier(), POLICY_EVALUATION)).satisfies(
                state -> {
                    Assertions.assertThat(state.getStartedAt()).isNotNull();
                    Assertions.assertThat(state.getUpdatedAt()).isNotNull();
                    Assertions.assertThat(state.getStatus()).isEqualTo(COMPLETED);
                }
        );
    }
}
