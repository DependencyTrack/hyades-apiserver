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
                //MATCHES group regex
                new Object[]{PolicyCondition.Operator.MATCHES, "{'group': 'acme*','name': 'acme*','version': '>=v1.2*'}", "{'group': 'acme-app','name': 'acme-lib','version': 'v1.2.3'}", true},
                //Exact matches
                new Object[]{PolicyCondition.Operator.MATCHES, "{'group': 'acme-app','name': 'acme-lib','version': 'v1.2.3'}", "{'group': 'acme-app','name': 'acme-lib','version': 'v1.2.3'}", true},
                //Exact group does not match
                new Object[]{PolicyCondition.Operator.MATCHES, "{'group': 'org.hippo','name': 'acme-lib','version': 'v1.2.3'}", "{'group': 'acme-app','name': 'acme-lib','version': 'v1.2.3'}", false},
                //Name does not match regex
                new Object[]{PolicyCondition.Operator.MATCHES, "{'group': 'acme-app','name': '*acme-lib*','version': 'v1.2.3'}", "{'group': 'acme-app','name': 'good-foo-lib','version': 'v1.2.3'}", false},
                //Version regex does not match
                new Object[]{PolicyCondition.Operator.MATCHES, "{'group': 'acme-app','name': '*acme-lib*','version': 'v1.*'}", "{'group': 'acme-app','name': 'acme-lib','version': 'v2.2.3'}", false},
                //Does not match on exact group
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'group': 'diff-group','name': 'acme-lib','version': 'v1.2.3'}", "{'group': 'acme-app','name': 'acme-lib','version': 'v1.2.3'}", true},
                //Does not match on version range greater than or equal
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'group': 'acme-app','name': '*acme-lib*','version': '>=v2.2.2'}", "{'group': 'acme-app','name': 'acme-lib','version': 'v1.2.3'}", true},
                //Matches without group
                new Object[]{PolicyCondition.Operator.MATCHES, "{'name': 'Test Component','version': '1.0.0'}", "{'name': 'Test Component','version': '1.0.0'}", true},
                //Matches on wild card group - uncomment after fixing script builder
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'group': '*', 'name': 'Test Component', 'version': '1.0.0' }", "{ 'group': 'Anything', 'name': 'Test Component', 'version': '1.0.0' }", true},
                //Matches on wild card name
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'group': 'acme-app', 'name': '*', 'version': '1.0.0' }", "{ 'group': 'acme-app', 'name': 'Anything', 'version': '1.0.0' }", true},
                //Matches on wild card version
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'group': 'acme-app', 'name': 'Test Component', 'version': '>=*' }", "{ 'group': 'acme-app', 'name': 'Test Component', 'version': '4.4.4' }", true},
                  //Matches on empty policy - uncomment after fixing script builder
                //new Object[]{PolicyCondition.Operator.MATCHES, "{}", "{}", true},
                //Does not match on lower version
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{ 'version': '== 1.1.1' }", "{'version': '0.1.1'}", true},
                //Matches on equal version
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'version': '== 1.1.1' }", "{'version': '1.1.1'}", true},
                //Does not match on higher version
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{ 'version': '== 1.1.1' }", "{'version': '2.1.1'}", true},
                //No match with version not equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'version': '!= 1.1.1' }", "{ 'version': '1.1.1' }", false},
                //Matches with version not equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'version': '!= 1.1.1' }", "{'version': '2.1.1'}", true},
                //Matches with version not equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'version': '!= 1.1.1' }", "{'version': '0.1.1'}", true},
                //Matches with version greater than
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'version': '> 1.1.1' }", "{'version': '2.1.1'}", true},
                //Does not match on version greater than
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'version': '> 1.1.1' }", "{'version': '0.1.1'}", false},
                //Does not match on version equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{ 'version': '> 1.1.1' }", "{'version': '1.1.1'}", false},
                //No match with version greater than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{ 'version': '> 1.1.1' }", "{'version': '0.1.1'}", true},
                //No match with version equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{ 'version': '> 1.1.1' }", "{'version': '1.1.1'}", true},
                //No match with version greater than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{ 'version': '> 1.1.1' }", "{'version': '2.1.1'}", false},
                //Matches on version less than
                new Object[]{PolicyCondition.Operator.MATCHES, "{'version': '<1.1.1'}", "{'version': '0.1.1'}", true},
                //Does not match on version less than
                new Object[]{PolicyCondition.Operator.MATCHES, "{'version': '<1.1.1'}", "{'version': '2.1.1'}", false},
                //Does not match on equal version
                new Object[]{PolicyCondition.Operator.MATCHES, "{'version': '<1.1.1'}", "{'version': '1.1.1'}", false},
                //No match on version less than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'version': '<1.1.1'}", "{'version': '0.1.1'}", false},
                //No match on version less than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'version': '<1.1.1'}", "{'version': '2.1.1'}", true},
                //No match on equal version
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'version': '<1.1.1'}", "{'version': '1.1.1'}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{'version': '<=1.1.1'}", "{'version': '0.1.1'}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{'version': '<=1.1.1'}", "{'version': '2.1.1'}", false},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{'version': '<=1.1.1'}", "{'version': '1.1.1'}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'version': '<=1.1.1'}", "{'version': '0.1.1'}", false},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'version': '<=1.1.1'}", "{'version': '2.1.1'}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{'version': '<=1.1.1'}", "{'version': '1.1.1'}", false},
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
