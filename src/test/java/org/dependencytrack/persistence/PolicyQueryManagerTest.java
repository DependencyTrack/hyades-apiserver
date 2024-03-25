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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class PolicyQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testGetApplicablePolicies() {
        final var grandParentProject = new Project();
        grandParentProject.setName("grandParent");
        qm.persist(grandParentProject);

        final var parentProject = new Project();
        parentProject.setParent(grandParentProject);
        parentProject.setName("parent");
        qm.persist(parentProject);

        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("child");
        qm.persist(childProject);

        final Tag policyTag = qm.createTag("foo");
        qm.bind(parentProject, List.of(policyTag));

        final Tag nonPolicyTag = qm.createTag("bar");
        qm.bind(childProject, List.of(nonPolicyTag));

        final var globalPolicy = new Policy();
        globalPolicy.setName("globalPolicy");
        globalPolicy.setOperator(Policy.Operator.ANY);
        globalPolicy.setViolationState(Policy.ViolationState.FAIL);
        qm.persist(globalPolicy);

        final var tagPolicy = new Policy();
        tagPolicy.setName("tagPolicy");
        tagPolicy.setOperator(Policy.Operator.ANY);
        tagPolicy.setViolationState(Policy.ViolationState.FAIL);
        tagPolicy.setTags(List.of(policyTag));
        qm.persist(tagPolicy);

        final var inheritedPolicy = new Policy();
        inheritedPolicy.setName("inheritedPolicy");
        inheritedPolicy.setOperator(Policy.Operator.ANY);
        inheritedPolicy.setViolationState(Policy.ViolationState.FAIL);
        inheritedPolicy.setProjects(List.of(parentProject));
        inheritedPolicy.setIncludeChildren(true);
        qm.persist(inheritedPolicy);

        assertThat(qm.getApplicablePolicies(grandParentProject)).satisfiesExactly(
                policy -> assertThat(policy.getName()).isEqualTo("globalPolicy")
        );
        assertThat(qm.getApplicablePolicies(parentProject)).satisfiesExactly(
                policy -> assertThat(policy.getName()).isEqualTo("globalPolicy"),
                policy -> assertThat(policy.getName()).isEqualTo("tagPolicy"),
                policy -> assertThat(policy.getName()).isEqualTo("inheritedPolicy")
        );
        assertThat(qm.getApplicablePolicies(childProject)).satisfiesExactly(
                policy -> assertThat(policy.getName()).isEqualTo("globalPolicy"),
                policy -> assertThat(policy.getName()).isEqualTo("inheritedPolicy")
        );
    }

    @Test
    public void testRemoveProjectFromPolicies() {
        final Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);

        // Create multiple policies that all reference the project
        final Policy policy1 = qm.createPolicy("Test Policy 1", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy1.setProjects(List.of(project));
        qm.persist(policy1);
        final Policy policy2 = qm.createPolicy("Test Policy 2", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy2.setProjects(List.of(project));
        qm.persist(policy2);

        // Remove project from all policies and verify that the associations have indeed been cleared
        qm.removeProjectFromPolicies(project);
        assertThat(qm.getObjectById(Policy.class, policy1.getId()).getProjects()).isEmpty();
        assertThat(qm.getObjectById(Policy.class, policy2.getId()).getProjects()).isEmpty();
    }

}