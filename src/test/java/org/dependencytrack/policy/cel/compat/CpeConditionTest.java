package org.dependencytrack.policy.cel.compat;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.PolicyCondition.Operator.MATCHES;

@RunWith(JUnitParamsRunner.class)
public class CpeConditionTest extends PersistenceCapableTest {

    private Object[] parameters() {
        return new Object[]{
                // MATCHES with exact match
                new Object[]{MATCHES, "cpe:/a:acme:application:1.0.0", "cpe:/a:acme:application:1.0.0", true},
                // MATCHES with regex match
                new Object[]{MATCHES, "cpe:/a:acme:\\\\w+:[0-9].0.0", "cpe:/a:acme:application:1.0.0", true},
                // MATCHES with no match
                new Object[]{MATCHES, "cpe:/a:acme:application:1.0.0", "cpe:/a:acme:application:9.9.9", false},
                // NO_MATCH with no match
                new Object[]{Operator.NO_MATCH, "cpe:/a:acme:application:1.0.0", "cpe:/a:acme:application:9.9.9", true},
                // NO_MATCH with exact match
                new Object[]{Operator.NO_MATCH, "cpe:/a:acme:application:1.0.0", "cpe:/a:acme:application:1.0.0", false},
                // MATCHES with quotes
                new Object[]{MATCHES, "\"cpe:/a:acme:application:1.0.0", "\"cpe:/a:acme:application:1.0.0", true}
        };
    }


    @Test
    @Parameters(method = "parameters")
    public void testCondition(final Operator operator, final String conditionCpe, final String componentCpe, final boolean expectViolation) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.CPE, operator, conditionCpe);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setCpe(componentCpe);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

}
