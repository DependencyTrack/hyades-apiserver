package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class LicenseGroupCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String scriptSrc = """
                component.resolved_license.groups.exists(group, group.uuid == "%s")
                """.formatted(escapeQuotes(policyCondition.getValue()));

        if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
            return scriptSrc;
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
            return "!" + scriptSrc;
        }

        return null;
    }

}
