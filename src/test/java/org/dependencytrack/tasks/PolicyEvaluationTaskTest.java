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
        qm.getPersistenceManager().refresh(qm.getWorkflowStateByTokenAndStep(componentPolicyEvaluationEvent.getChainIdentifier(), POLICY_EVALUATION));
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
        qm.getPersistenceManager().refresh(qm.getWorkflowStateByTokenAndStep(projectPolicyEvaluationTaskEvent.getChainIdentifier(), POLICY_EVALUATION));
        Assertions.assertThat(qm.getWorkflowStateByTokenAndStep(projectPolicyEvaluationTaskEvent.getChainIdentifier(), POLICY_EVALUATION)).satisfies(
                state -> {
                    Assertions.assertThat(state.getStartedAt()).isNotNull();
                    Assertions.assertThat(state.getUpdatedAt()).isNotNull();
                    Assertions.assertThat(state.getStatus()).isEqualTo(COMPLETED);
                }
        );
    }
}
