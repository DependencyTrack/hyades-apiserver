package org.dependencytrack.policy.cel.compat;

import com.github.packageurl.PackageURL;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@RunWith(JUnitParamsRunner.class)
public class PackageUrlConditionTest extends AbstractPostgresEnabledTest {

    private Object[] parameters() {
        return new Object[]{
                //Matches with exact match
                new Object[]{PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0", true},
                //matching on null purl - invalid. We cannot pass null for purl
                //new Object[]{PolicyCondition.Operator.NO_MATCH, ".+", "", true},
                //No Match exact
                new Object[]{PolicyCondition.Operator.NO_MATCH, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/web-component@6.9", true},
                //Wrong operator
                new Object[]{PolicyCondition.Operator.IS, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0", false},
                //Exact match
                new Object[]{PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0", true},
                //Matches with qualifier also
                new Object[]{PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0?type=jar", true},
                //Partial match
                new Object[]{PolicyCondition.Operator.MATCHES, "/com/acme/", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
                //Partial match
                new Object[]{PolicyCondition.Operator.MATCHES, "/com.acme/", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
                //Matches on wild card
                new Object[]{PolicyCondition.Operator.MATCHES, ".*com.acme.*", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
                //Matches on wild card
                new Object[]{PolicyCondition.Operator.MATCHES, ".*acme.*myCompany.*", "pkg:generic/com/acme/example-component@1.0-myCompanyFix-1?type=jar", true},
                //Matches on wild card
                new Object[]{PolicyCondition.Operator.MATCHES, ".*(a|b|c)cme.*", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
        };
    }

    @Test
    @Parameters(method = "parameters")
    public void testCondition(final PolicyCondition.Operator operator, final String conditionPurl, final String componentPurl, final boolean expectViolation) throws Exception{
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, operator, conditionPurl);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL(componentPurl));
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            List<PolicyViolation> violations = qm.getAllPolicyViolations(component);
            assertThat(violations).hasSize(1);
            PolicyViolation violation = violations.get(0);
            assertEquals(component, violation.getComponent());
            assertEquals(condition, violation.getPolicyCondition());
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

}
