package org.dependencytrack.policy.cel.compat;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnitParamsRunner.class)
public class CoordinatesConditionTest extends AbstractPostgresEnabledTest {
    private Object[] parameters() {
        return new Object[]{
                // MATCHES regex
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme*\",\"name\": \"acme*\",\"version\": \">=v1.2*\"}", "{\"group\": \"acme-app\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", true},
                //Exact match
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", true},
                //Group does not match
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"org.hippo\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", false},
                //Name does not match regex
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\",\"name\": \"*acme-lib*\",\"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\",\"name\": \"good-foo-lib\",\"version\": \"v1.2.3\"}", false},
                //Version does not match
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\",\"name\": \"*acme-lib*\",\"version\": \"v1.*\"}", "{\"group\": \"acme-app\",\"name\": \"acme-lib\",\"version\": \"v2.2.3\"}", false},
                //Does not match on group
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"group\": \"diff-group\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", true},
                //Does not match on version
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"group\": \"acme-app\",\"name\": \"*acme-lib*\",\"version\": \">=v2.2.2\"}", "{\"group\": \"acme-app\",\"name\": \"acme-lib\",\"version\": \"v1.2.3\"}", true},
        };
    }

    @Test
    @Parameters(method = "parameters")
    public void testCondition(final PolicyCondition.Operator operator, final String conditionCoordinates, final String componentCoordinates, final boolean expectViolation) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, operator, conditionCoordinates);

        final JSONObject def = new JSONObject(componentCoordinates);
        final String group = Optional.ofNullable(def.optString("group", null)).orElse("");
        final String name = Optional.ofNullable(def.optString("name", null)).orElse("");
        final String version = Optional.ofNullable(def.optString("version")).orElse("");

        final var project = new Project();
        project.setName(group);
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup(group);
        component.setName(name);
        component.setVersion(version);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }
}
