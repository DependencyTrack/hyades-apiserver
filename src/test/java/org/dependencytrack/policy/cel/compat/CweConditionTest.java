package org.dependencytrack.policy.cel.compat;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnitParamsRunner.class)
public class CweConditionTest extends AbstractPostgresEnabledTest {
    private Object[] parameters() {
        return new Object[]{
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.INFO, PolicyCondition.Operator.CONTAINS_ANY,
                        "CWE-123", 123, 0, true, PolicyViolation.Type.SECURITY, Policy.ViolationState.INFO},
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.FAIL, PolicyCondition.Operator.CONTAINS_ALL,
                        "CWE-123, CWE-786", 123, 786, true, PolicyViolation.Type.SECURITY, Policy.ViolationState.FAIL},
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.FAIL, PolicyCondition.Operator.IS,
                        "CWE-123, CWE-786", 123, 786, false, null, null},
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.FAIL, PolicyCondition.Operator.CONTAINS_ALL,
                        "CWE-123.565, CWE-786.67", 123, 786, false, null, null},
        };
    }

    @Test
    @Parameters(method = "parameters")
    public void testSingleCwe(Policy.Operator policyOperator, Policy.ViolationState violationState,
                              PolicyCondition.Operator conditionOperator, String inputConditionCwe, int inputCweId, int inputCweId2,
                              boolean expectViolation, PolicyViolation.Type actualType, Policy.ViolationState actualViolationState) {
        Policy policy = qm.createPolicy("Test Policy", policyOperator, violationState);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.CWE, conditionOperator, inputConditionCwe);
        final var project = new Project();
        project.setName("acme-app");
        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.addCwe(inputCweId);
        if (inputCweId2 != 0) {
            vulnerability.addCwe(inputCweId2);
        }
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getSubject()).isEqualTo(PolicyCondition.Subject.CWE);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getViolationType()).isEqualTo(actualType);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getPolicy().getViolationState()).isEqualTo(actualViolationState);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

}
