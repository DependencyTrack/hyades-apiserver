package org.dependencytrack.policy.cel.compat;

import alpine.common.logging.Logger;
import org.dependencytrack.model.PolicyCondition;

import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;

public class ComponentAgePolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {
    private static final Logger LOGGER = Logger.getLogger(ComponentAgePolicyScriptSourceBuilder.class);

    @Override
    public String apply(PolicyCondition policyCondition) {
//        if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
//            return """
//                    vulns.exists(vuln, vuln.severity == "%s")
//                    """.formatted(escapeQuotes(policyCondition.getValue()));
//        } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
//            return """
//                    vulns.exists(vuln, vuln.severity != "%s")
//                    """.formatted(escapeQuotes(policyCondition.getValue()));
//        }
//
//        return null;
//    }

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

        final LocalDate publishedDate = LocalDate.ofInstant(published.toInstant(), ZoneId.systemDefault());
        final LocalDate ageDate = publishedDate.plus(agePeriod);
        final LocalDate today = LocalDate.now(ZoneId.systemDefault());

        return switch (policyCondition.getOperator()) {
            case NUMERIC_GREATER_THAN -> ageDate.isBefore(today);
            case NUMERIC_GREATER_THAN_OR_EQUAL -> ageDate.isEqual(today) || ageDate.isBefore(today);
            case NUMERIC_EQUAL -> ageDate.isEqual(today);
            case NUMERIC_NOT_EQUAL -> !ageDate.isEqual(today);
            case NUMERIC_LESSER_THAN_OR_EQUAL -> ageDate.isEqual(today) || ageDate.isAfter(today);
            case NUMERIC_LESS_THAN -> ageDate.isAfter(LocalDate.now(ZoneId.systemDefault()));
            default -> {
                LOGGER.warn("Operator %s is not supported for component age conditions".formatted(condition.getOperator()));
                yield false;
            }
        };
    }
}