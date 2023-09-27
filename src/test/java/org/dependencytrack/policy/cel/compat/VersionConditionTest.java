package org.dependencytrack.policy.cel.compat;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnitParamsRunner.class)
public class VersionConditionTest extends AbstractPostgresEnabledTest {

    private Object[] parameters() {
        return new Object[]{
                // MATCHES with exact match
                new Object[]{PolicyCondition.Operator.NUMERIC_EQUAL, "v1.2.3", "v1.2.3", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_EQUAL, "v1.2.3", "v1.2.4", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "0.4.5-SNAPSHOT", "0.4.5", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "0.4.5", "0.4.5", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN, "0.4.5", "0.5.5", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN, "0.4.4", "0.4.4", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "0.4.4", "0.4.4", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "v0.4.5-SNAPSHOT", "z0.4.5", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "v0.4.5-SNAPSHOT", "0.4.5", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "v0.4.*", "v0.4.1", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESS_THAN, "v0.4.*", "v0.4.1", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESS_THAN, "v0.4.*", "v0.3.1", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "v0.4.*", "v0.4.0", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "v0.4.*", "v0.4.2", false},
        };
    }

    @Test
    @Parameters(method = "parameters")
    public void testCondition(final PolicyCondition.Operator operator, final String conditionVersion, final String componentVersion, final boolean expectViolation) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, operator, conditionVersion);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion(componentVersion);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }
}
