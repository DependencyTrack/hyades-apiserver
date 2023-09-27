package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class SeverityCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
            return """
                    vulns.exists(vuln, vuln.severity == "%s")
                    """.formatted(escapeQuotes(policyCondition.getValue()));
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
            return """
                    vulns.exists(vuln, vuln.severity != "%s")
                    """.formatted(escapeQuotes(policyCondition.getValue()));
        }

        return null;
    }

}
