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

import org.dependencytrack.model.PolicyCondition;

import java.util.function.Function;
import java.util.regex.Pattern;

public interface CelPolicyScriptSourceBuilder extends Function<PolicyCondition, String> {

    Pattern QUOTES_PATTERN = Pattern.compile("\"");

    static String escapeQuotes(final String value) {
        return QUOTES_PATTERN.matcher(value).replaceAll("\\\\\"");
    }

}
