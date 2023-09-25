package org.dependencytrack.policy.cel.compat;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Policy.ViolationState;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation.Type;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnitParamsRunner.class)
public class HashConditionTest extends AbstractPostgresEnabledTest {

    private Object[] parameters() {
        return new Object[]{
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': 'SHA256', 'value': 'test_hash' }",
                        "test_hash", true, ViolationState.FAIL, Type.OPERATIONAL, ViolationState.FAIL},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': 'SHA256', 'value': 'test_hash' }",
                        "test_hash", true, ViolationState.WARN, Type.OPERATIONAL, ViolationState.WARN},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': 'SHA256', 'value': 'test_hash' }",
                        "test_hash_false", false, ViolationState.INFO, Type.OPERATIONAL, ViolationState.INFO},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': 'test', 'value': 'test_hash' }",
                        "test_hash", false, ViolationState.INFO, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS_NOT, "{ 'algorithm': 'SHA256', 'value': 'test_hash' }",
                        "test_hash20", false, ViolationState.INFO, null, null},
                new Object[]{Policy.Operator.ANY, Operator.MATCHES, "{ 'algorithm': 'SHA256', 'value': 'test_hash' }",
                        "test_hash", false, ViolationState.INFO, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': null, 'value': 'test_hash' }",
                        "test_hash", false, ViolationState.FAIL, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': 'MD5', 'value': null }",
                        "test_hash", false, ViolationState.FAIL, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': 'SHA256', 'value': '' }",
                        "test_hash", false, ViolationState.FAIL, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ 'algorithm': '', 'value': 'test_hash' }",
                        "test_hash", false, ViolationState.FAIL, null, null},
        };
    }

    @Test
    @Parameters(method = "parameters")
    public void testCondition(Policy.Operator policyOperator, final Operator condition, final String conditionHash,
                              final String actualHash, final boolean expectViolation, ViolationState violationState,
                              Type actualType, ViolationState actualViolationState) {
        final Policy policy = qm.createPolicy("policy", policyOperator, violationState);
        qm.createPolicyCondition(policy, Subject.COMPONENT_HASH, condition, conditionHash);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setSha256(actualHash);
        qm.persist(component);


        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getViolationType()).isEqualTo(actualType);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getPolicy().getViolationState()).isEqualTo(actualViolationState);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }


    @Test
    public void testWithNullPolicyCondition() {

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setSha256("actualHash");
        qm.persist(component);
        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

}
