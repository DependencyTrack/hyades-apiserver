package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.PolicyEngine;

/**
 * A {@link Subscriber} task that executes policy evaluations for {@link Project}s or {@link Component}s.
 *
 * @since 5.0.0
 */
public class PolicyEvaluationTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(PolicyEvaluationTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final ProjectPolicyEvaluationEvent event) {
            try {
                new PolicyEngine().evaluateProject(event.getUuid());
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while evaluating policies for project " + event.getUuid(), ex);
            }
        } else if (e instanceof final ComponentPolicyEvaluationEvent event) {
            try {
                new PolicyEngine().evaluate(event.getUuid());
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while evaluating policies for component " + event.getUuid(), ex);
            }
        }
    }

}
