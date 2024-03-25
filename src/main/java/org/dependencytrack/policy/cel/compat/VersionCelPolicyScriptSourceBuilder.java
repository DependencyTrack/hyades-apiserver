package org.dependencytrack.policy.cel.compat;

import alpine.common.logging.Logger;
import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import io.github.nscuro.versatile.version.VersioningScheme;
import org.dependencytrack.model.PolicyCondition;

public class VersionCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {
    private static final Logger LOGGER = Logger.getLogger(VersionCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(PolicyCondition policyCondition) {

        Vers conditionVers = evaluateVers(policyCondition);
        if (conditionVers == null) {
            return null;
        }
        return """
                component.matches_range("%s")
                """.formatted(conditionVers.toString());
    }

    private static Vers evaluateVers(final PolicyCondition policyCondition) {
        try {
            switch (policyCondition.getOperator()) {
                case NUMERIC_EQUAL:
                    return Vers.builder(VersioningScheme.GENERIC)
                            .withConstraint(Comparator.EQUAL, policyCondition.getValue())
                            .build();
                case NUMERIC_NOT_EQUAL:
                    return Vers.builder(VersioningScheme.GENERIC)
                            .withConstraint(Comparator.NOT_EQUAL, policyCondition.getValue())
                            .build();
                case NUMERIC_LESS_THAN:
                    return Vers.builder(VersioningScheme.GENERIC)
                            .withConstraint(Comparator.LESS_THAN, policyCondition.getValue())
                            .build();
                case NUMERIC_LESSER_THAN_OR_EQUAL:
                    return Vers.builder(VersioningScheme.GENERIC)
                            .withConstraint(Comparator.LESS_THAN_OR_EQUAL, policyCondition.getValue())
                            .build();
                case NUMERIC_GREATER_THAN:
                    return Vers.builder(VersioningScheme.GENERIC)
                            .withConstraint(Comparator.GREATER_THAN, policyCondition.getValue())
                            .build();
                case NUMERIC_GREATER_THAN_OR_EQUAL:
                    return Vers.builder(VersioningScheme.GENERIC)
                            .withConstraint(Comparator.GREATER_THAN_OR_EQUAL, policyCondition.getValue())
                            .build();
                default:
                    LOGGER.warn("Unsupported operation " + policyCondition.getOperator());
                    return null;
            }
        } catch (VersException versException) {
            LOGGER.warn("Unable to parse version range in policy condition", versException);
            return null;
        }
    }
}
