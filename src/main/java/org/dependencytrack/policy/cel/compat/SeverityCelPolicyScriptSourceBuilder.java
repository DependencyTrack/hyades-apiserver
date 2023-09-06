package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

public class SeverityCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String escapedPolicyValue = escapeJson(policyCondition.getValue());

        if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
            return """
                    vulns.exists(vuln, vuln.severity == "%s")
                    """.formatted(escapedPolicyValue);
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
            return """
                    vulns.exists(vuln, vuln.severity != "%s")
                    """.formatted(escapedPolicyValue);
        }

        return null;
    }

}
