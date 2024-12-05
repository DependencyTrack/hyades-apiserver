/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
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
import org.dependencytrack.util.WaitingLockConfiguration;
import org.slf4j.MDC;

import java.time.Duration;
import java.time.Instant;

import static org.dependencytrack.common.MdcKeys.MDC_COMPONENT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.model.WorkflowStep.POLICY_EVALUATION;
import static org.dependencytrack.util.LockProvider.executeWithLockWaiting;

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
        try {
            if (e instanceof final ProjectPolicyEvaluationEvent event) {
                executeWithLockWaiting(createLockConfiguration(event), () -> evaluateProject(event));
            } else if (e instanceof final ComponentPolicyEvaluationEvent event) {
                executeWithLockWaiting(createLockConfiguration(event), () -> evaluateComponent(event));
            }
        } catch (Throwable t) {
            LOGGER.error("Failed to execute policy evaluation", t);
        }
    }

    private void evaluateProject(final ProjectPolicyEvaluationEvent event) {
        WorkflowState projectPolicyEvaluationState;
        try (final var qm = new QueryManager()) {
            projectPolicyEvaluationState = qm.updateStartTimeIfWorkflowStateExists(event.getChainIdentifier(), POLICY_EVALUATION);
            try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, event.getUuid().toString())) {
                new CelPolicyEngine().evaluateProject(event.getUuid());
                qm.updateWorkflowStateToComplete(projectPolicyEvaluationState);
            } catch (Exception ex) {
                qm.updateWorkflowStateToFailed(projectPolicyEvaluationState, ex.getMessage());
                LOGGER.error("An unexpected error occurred while evaluating policies for project " + event.getUuid(), ex);
            }
        }
    }

    private void evaluateComponent(final ComponentPolicyEvaluationEvent event) {
        WorkflowState componentMetricsEvaluationState;
        try (final var qm = new QueryManager()) {
            componentMetricsEvaluationState = qm.updateStartTimeIfWorkflowStateExists(event.getChainIdentifier(), POLICY_EVALUATION);
            try (var ignoredMdcComponentUuid = MDC.putCloseable(MDC_COMPONENT_UUID, event.getUuid().toString())) {
                new CelPolicyEngine().evaluateComponent(event.getUuid());
                qm.updateWorkflowStateToComplete(componentMetricsEvaluationState);
            } catch (Exception ex) {
                qm.updateWorkflowStateToFailed(componentMetricsEvaluationState, ex.getMessage());
                LOGGER.error("An unexpected error occurred while evaluating policies for component " + event.getUuid(), ex);
            }
        }
    }

    private static WaitingLockConfiguration createLockConfiguration(final ProjectPolicyEvaluationEvent event) {
        return new WaitingLockConfiguration(
                /* createdAt */ Instant.now(),
                /* name */ "%s-project-%s".formatted(PolicyEvaluationTask.class.getSimpleName(), event.getUuid()),
                /* lockAtMostFor */ Duration.ofMinutes(5),
                /* lockAtLeastFor */ Duration.ZERO,
                /* pollInterval */ Duration.ofMillis(100),
                /* waitTimeout */ Duration.ofMinutes(5));
    }

    private static WaitingLockConfiguration createLockConfiguration(final ComponentPolicyEvaluationEvent event) {
        return new WaitingLockConfiguration(
                /* createdAt */ Instant.now(),
                /* name */ "%s-component-%s".formatted(PolicyEvaluationTask.class.getSimpleName(), event.getUuid()),
                /* lockAtMostFor */ Duration.ofMinutes(1),
                /* lockAtLeastFor */ Duration.ZERO,
                /* pollInterval */ Duration.ofMillis(100),
                /* waitTimeout */ Duration.ofMinutes(1));
    }

}
