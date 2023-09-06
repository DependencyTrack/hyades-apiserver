package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import java.util.function.Function;

public interface CelPolicyScriptSourceBuilder extends Function<PolicyCondition, String> {
}
