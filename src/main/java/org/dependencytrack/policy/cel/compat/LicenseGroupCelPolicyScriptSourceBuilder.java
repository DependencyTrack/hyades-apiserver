package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

public class LicenseGroupCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String scriptSrc = """
                component.resolved_license.groups.exists(group, group.uuid == "%s")
                """.formatted(escapeJson(policyCondition.getValue()));

        if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
            return scriptSrc;
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
            return "!" + scriptSrc;
        }

        return null;
    }

}
