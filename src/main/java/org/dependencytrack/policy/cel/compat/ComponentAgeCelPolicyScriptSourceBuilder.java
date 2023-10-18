package org.dependencytrack.policy.cel.compat;

import alpine.common.logging.Logger;
import org.dependencytrack.model.PolicyCondition;

import java.time.Period;
import java.time.format.DateTimeParseException;

public class ComponentAgeCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {
    private static final Logger LOGGER = Logger.getLogger(ComponentAgeCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(PolicyCondition policyCondition) {
        final Period agePeriod;
        try {
            agePeriod = Period.parse(policyCondition.getValue());
        } catch (DateTimeParseException e) {
            LOGGER.error("Invalid age duration format", e);
            return null;
        }

        if (agePeriod.isZero() || agePeriod.isNegative()) {
            LOGGER.warn("Age durations must not be zero or negative");
            return null;
        }

        PolicyCondition.Operator operatorResult = switch (policyCondition.getOperator().toString()) {
            case "NUMERIC_GREATER_THAN", ">" -> PolicyCondition.Operator.NUMERIC_GREATER_THAN;
            case "NUMERIC_GREATER_THAN_OR_EQUAL", ">=" -> PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL;
            case "NUMERIC_EQUAL", "==" -> PolicyCondition.Operator.NUMERIC_EQUAL;
            case "NUMERIC_NOT_EQUAL", "!=" -> PolicyCondition.Operator.NUMERIC_NOT_EQUAL;
            case "NUMERIC_LESSER_THAN_OR_EQUAL", "<=" -> PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL;
            case "NUMERIC_LESS_THAN", "<" -> PolicyCondition.Operator.NUMERIC_LESS_THAN;
            default -> {
                LOGGER.warn("Operator %s is not supported for component age conditions".formatted(policyCondition.getOperator()));
                yield null;
            }

        };

        return """
                component.compare_component_age("%s", "%s")
                    """.formatted(CelPolicyScriptSourceBuilder.escapeQuotes(agePeriod.toString()), operatorResult);
    }
}