package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

public class SwidTagIdCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String scriptSrc = """
                component.swid_tag_id.matches("%s")
                """.formatted(escapeJson(policyCondition.getValue()));

        if (policyCondition.getOperator() == PolicyCondition.Operator.MATCHES) {
            return scriptSrc;
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.NO_MATCH) {
            return "!" + scriptSrc;
        }

        return null;
    }

}