package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;
import org.json.JSONObject;

import java.util.Optional;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

public class CoordinatesCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition condition) {
        if (condition.getValue() == null) {
            return null;
        }

        final JSONObject def = new JSONObject(condition.getValue());
        final String group = Optional.ofNullable(def.optString("group", null)).orElse(".*");
        final String name = Optional.ofNullable(def.optString("name", null)).orElse(".*");
        final String version = Optional.ofNullable(def.optString("version")).orElse(".*");

        final var scriptSrc = """
                component.group.matches("%s") && component.name.matches("%s") && component.version.matches("%s")
                """.formatted(escapeJson(group), escapeJson(name), escapeJson(version));
        if (condition.getOperator() == PolicyCondition.Operator.MATCHES) {
            return scriptSrc;
        } else if (condition.getOperator() == PolicyCondition.Operator.NO_MATCH) {
            return "!(%s)".formatted(scriptSrc);
        }

        return null;
    }

}
