package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

public class VersionDistanceCelScriptBuilder implements CelPolicyScriptSourceBuilder {
    @Override
    public String apply(PolicyCondition policyCondition) {
        return """
                component.version_distance("%s", %s)
                    """.formatted(comparator(policyCondition.getOperator()), policyCondition.getValue());
    }

    private String comparator (PolicyCondition.Operator operator) {
        return switch (operator) {
            case NUMERIC_GREATER_THAN  -> ">";
            case NUMERIC_GREATER_THAN_OR_EQUAL -> ">=";
            case NUMERIC_EQUAL -> "==";
            case NUMERIC_NOT_EQUAL -> "!=";
            case NUMERIC_LESSER_THAN_OR_EQUAL -> "<=";
            case NUMERIC_LESS_THAN  -> "<";
            default -> "";
        };
    }
}
