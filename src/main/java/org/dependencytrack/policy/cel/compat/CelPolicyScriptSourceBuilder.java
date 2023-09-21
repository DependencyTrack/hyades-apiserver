package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import java.util.function.Function;
import java.util.regex.Pattern;

public interface CelPolicyScriptSourceBuilder extends Function<PolicyCondition, String> {

    Pattern QUOTES_PATTERN = Pattern.compile("\"");

    static String escapeQuotes(final String value) {
        return QUOTES_PATTERN.matcher(value).replaceAll("\\\\\"");
    }

}
