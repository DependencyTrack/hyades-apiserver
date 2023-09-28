package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class PackageUrlCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String scriptSrc = """
                component.purl.matches("%s")
                """.formatted(escapeQuotes(policyCondition.getValue()));

        if (policyCondition.getOperator() == PolicyCondition.Operator.MATCHES) {
            return scriptSrc;
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.NO_MATCH) {
            return "!" + scriptSrc;
        }

        return null;
    }

}
