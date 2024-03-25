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
package org.dependencytrack.policy.cel.compat;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnitParamsRunner.class)
public class ComponentAgeCelPolicyTest extends PersistenceCapableTest {

    private Object[] parameters() {
        return new Object[]{
                new Object[]{Instant.now().minus(Duration.ofDays(667)), PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P666D", true},
                new Object[]{Instant.now().minus(Duration.ofDays(667)), PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P666D", true},
                new Object[]{Instant.now().minus(Duration.ofDays(667)), PolicyCondition.Operator.NUMERIC_EQUAL, "P666D", false},
                new Object[]{Instant.now().minus(Duration.ofDays(667)), PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "P666D", true},
                new Object[]{Instant.now().minus(Duration.ofDays(667)), PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "P666D", false},
                new Object[]{Instant.now().minus(Duration.ofDays(667)), PolicyCondition.Operator.NUMERIC_LESS_THAN, "P666D", false},
                // Component is newer by one day.
                new Object[]{Instant.now().minus(Duration.ofDays(665)), PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P666D", false},
                new Object[]{Instant.now().minus(Duration.ofDays(665)), PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P666D", false},
                new Object[]{Instant.now().minus(Duration.ofDays(665)), PolicyCondition.Operator.NUMERIC_EQUAL, "P666D", false},
                new Object[]{Instant.now().minus(Duration.ofDays(665)), PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "P666D", true},
                new Object[]{Instant.now().minus(Duration.ofDays(665)), PolicyCondition.Operator.NUMERIC_LESS_THAN, "P666D", true},
                // Component is exactly as old.
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P666D", false},
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P666D", true},
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_EQUAL, "P666D", true},
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "P666D", false},
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "P666D", true},
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_LESS_THAN, "P666D", false},
                // Unsupported operator.
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.MATCHES, "P666D", false},
                // Negative age period.
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_EQUAL, "P-666D", false},
                // Invalid age period format.
                new Object[]{Instant.now().minus(Duration.ofDays(666)), PolicyCondition.Operator.NUMERIC_EQUAL, "foobar", false},
                // No known publish date.
                new Object[]{null, PolicyCondition.Operator.NUMERIC_EQUAL, "P666D", false},
        };
    }

    @Test
    @Parameters(method = "parameters")
    public void evaluateTest(Instant publishedDate, PolicyCondition.Operator operator, String ageValue, boolean shouldViolate) {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final var condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.AGE, operator, ageValue);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);
        final var component = new Component();
        component.setName("test component");
        component.setPurl("pkg:maven/foo/bar@1.2.3");
        component.setProject(project);
        qm.persist(component);
        final var metaComponent = new IntegrityMetaComponent();
        metaComponent.setRepositoryUrl("test");
        metaComponent.setStatus(FetchStatus.PROCESSED);
        metaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        if (publishedDate != null) {
            metaComponent.setPublishedAt(Date.from(publishedDate));
        }
        metaComponent.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(metaComponent);


        new CelPolicyEngine().evaluateProject(project.getUuid());

        if (shouldViolate) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
            final PolicyViolation violation = qm.getAllPolicyViolations(component).get(0);
            assertThat(violation.getComponent()).isEqualTo(component);
            assertThat(violation.getPolicyCondition()).isEqualTo(condition);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }


}
