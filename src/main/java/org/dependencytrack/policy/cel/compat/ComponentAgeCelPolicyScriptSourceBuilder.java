package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

public class ComponentAgeCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {
    @Override
    public String apply(PolicyCondition policyCondition) {

        return """
                component.compare_age("%s", "%s")
                    """.formatted(policyCondition.getOperator(), CelPolicyScriptSourceBuilder.escapeQuotes(policyCondition.getValue()));
    }
}