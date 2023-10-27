package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

public class VersionDistanceCelScriptBuilder implements CelPolicyScriptSourceBuilder {
    @Override
    public String apply(PolicyCondition policyCondition) {
        return """
                component.version_distance("%s", "%s")
                    """.formatted(CelPolicyScriptSourceBuilder.escapeQuotes(policyCondition.getValue()), policyCondition.getOperator());
    }
}
