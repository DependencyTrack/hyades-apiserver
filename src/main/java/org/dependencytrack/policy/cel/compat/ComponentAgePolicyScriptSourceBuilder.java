package org.dependencytrack.policy.cel.compat;

import alpine.common.logging.Logger;
import org.dependencytrack.model.PolicyCondition;

import java.time.Period;
import java.time.format.DateTimeParseException;

public class ComponentAgePolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {
    private static final Logger LOGGER = Logger.getLogger(ComponentAgePolicyScriptSourceBuilder.class);

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
        return switch (policyCondition.getOperator()) {
            case NUMERIC_GREATER_THAN -> """
                    component.compare_component_age(<%s)
                    """.formatted(agePeriod);//ageDate.isBefore(today);
            case NUMERIC_GREATER_THAN_OR_EQUAL -> """
                    component.compare_component_age(<=%s)
                    """.formatted(agePeriod); //ageDate.isEqual(today) || ageDate.isBefore(today);
            case NUMERIC_EQUAL -> """
                    component.compare_component_age(%s_EQUAL)
                    """.formatted(agePeriod);// ageDate.isEqual(today);
            case NUMERIC_NOT_EQUAL -> """
                    component.compare_component_age(!=%s)
                    """.formatted(agePeriod);//!ageDate.isEqual(today);
            case NUMERIC_LESSER_THAN_OR_EQUAL -> """
                    component.compare_component_age(<=%s)
                    """.formatted(agePeriod); //ageDate.isEqual(today) || ageDate.isAfter(today);
            case NUMERIC_LESS_THAN -> """
                    component.compare_component_age(<=%s)
                    """.formatted(agePeriod);// ageDate.isAfter(LocalDate.now(ZoneId.systemDefault()));
            default -> {
                LOGGER.warn("Operator %s is not supported for component age conditions".formatted(policyCondition.getOperator()));
                yield null;
            }
        };

    }
}