/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.policy.cel.compat;

import alpine.common.logging.Logger;
import org.cyclonedx.model.Hash;
import org.dependencytrack.model.PolicyCondition;
import org.json.JSONObject;

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class ComponentHashCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = Logger.getLogger(ComponentHashCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final Hash hash = extractHashValues(policyCondition);
        if (hash.getAlgorithm() == null || hash.getValue() == null || hash.getAlgorithm().isEmpty() || hash.getValue().isEmpty()) {
            return null;
        }

        final String fieldName = hash.getAlgorithm().toLowerCase().replaceAll("-", "_");
        if (org.dependencytrack.proto.policy.v1.Component.getDescriptor().findFieldByName(fieldName) == null) {
            LOGGER.warn("Component does not have a field named %s".formatted(fieldName));
            return null;
        }
        if (policyCondition.getOperator().equals(PolicyCondition.Operator.IS)) {
            return """
                    component.%s == "%s"
                    """.formatted(fieldName, escapeQuotes(hash.getValue()));
        } else {
            LOGGER.warn("Policy operator %s is not allowed with this policy".formatted(policyCondition.getOperator().toString()));
            return null;
        }
    }

    private static Hash extractHashValues(PolicyCondition condition) {
        //Policy condition received here will never be null
        final JSONObject def = new JSONObject(condition.getValue());
        return new Hash(
                def.optString("algorithm", null),
                def.optString("value", null)
        );
    }

}
