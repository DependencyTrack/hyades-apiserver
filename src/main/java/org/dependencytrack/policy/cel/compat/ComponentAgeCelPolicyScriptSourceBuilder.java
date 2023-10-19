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

        return """
                component.compare_age("%s", "%s")
                    """.formatted(CelPolicyScriptSourceBuilder.escapeQuotes(agePeriod.toString()), policyCondition.getOperator());
    }
}