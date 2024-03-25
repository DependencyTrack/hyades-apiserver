package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.cel.CelPolicyEngine;

import java.util.UUID;

import static org.dependencytrack.model.WorkflowStep.POLICY_EVALUATION;

/**
 * A {@link Subscriber} task that executes policy evaluations for {@link Project}s or {@link Component}s.
 *
 * @since 5.0.0
 */
public class PolicyEvaluationTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(PolicyEvaluationTask.class);


    public PolicyEvaluationTask() {
    }


    @Override
    public void inform(final Event e) {
        if (e instanceof final ProjectPolicyEvaluationEvent event) {
            WorkflowState projectPolicyEvaluationState;
            try (final var qm = new QueryManager()) {
                projectPolicyEvaluationState = qm.updateStartTimeIfWorkflowStateExists(event.getChainIdentifier(), POLICY_EVALUATION);
                try {
                    evaluateProject(event.getUuid());
                    qm.updateWorkflowStateToComplete(projectPolicyEvaluationState);
                } catch (Exception ex) {
                    qm.updateWorkflowStateToFailed(projectPolicyEvaluationState, ex.getMessage());
                    LOGGER.error("An unexpected error occurred while evaluating policies for project " + event.getUuid(), ex);
                }
            }
        } else if (e instanceof final ComponentPolicyEvaluationEvent event) {
            WorkflowState componentMetricsEvaluationState;
            try (final var qm = new QueryManager()) {
                componentMetricsEvaluationState = qm.updateStartTimeIfWorkflowStateExists(event.getChainIdentifier(), POLICY_EVALUATION);
                try {
                    evaluateComponent(event.getUuid());
                    qm.updateWorkflowStateToComplete(componentMetricsEvaluationState);
                } catch (Exception ex) {
                    qm.updateWorkflowStateToFailed(componentMetricsEvaluationState, ex.getMessage());
                    LOGGER.error("An unexpected error occurred while evaluating policies for component " + event.getUuid(), ex);
                }
            }
        }
    }

    private void evaluateProject(final UUID uuid) {
        new CelPolicyEngine().evaluateProject(uuid);
    }

    private void evaluateComponent(final UUID uuid) {
        new CelPolicyEngine().evaluateComponent(uuid);

    }

}
