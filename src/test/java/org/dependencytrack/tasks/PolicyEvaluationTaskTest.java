package org.dependencytrack.tasks;

import org.assertj.core.api.Assertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.util.List;
import java.util.UUID;

import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStep.POLICY_EVALUATION;

public class PolicyEvaluationTaskTest extends PersistenceCapableTest {

    @Test
    public void testWorkflowStateIsCompletedForComponent() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setResolvedLicense(license);
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE, PolicyCondition.Operator.IS, license.getUuid().toString());

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

        var projectPolicyEvaluationTaskEvent = new ProjectPolicyEvaluationEvent(project.getUuid());
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
