package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

public class PackageUrlCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String scriptSrc = """
                component.purl.matches("%s")
                """.formatted(escapeJson(policyCondition.getValue()));

        if (policyCondition.getOperator() == PolicyCondition.Operator.MATCHES) {
            return scriptSrc;
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.NO_MATCH) {
            return "!" + scriptSrc;
        }

        return null;
    }

}
