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
package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Decl;
import com.google.api.expr.v1alpha1.Type;
import org.dependencytrack.policy.cel.definition.CelPolicyTypes;
import org.projectnessie.cel.checker.Decls;

enum CelPolicyVariable {

    COMPONENT("component", CelPolicyTypes.TYPE_COMPONENT),
    PROJECT("project", CelPolicyTypes.TYPE_PROJECT),
    VULN("vuln", CelPolicyTypes.TYPE_VULNERABILITY),
    VULNS("vulns", CelPolicyTypes.TYPE_VULNERABILITIES),
    NOW("now", Decls.Timestamp);

    private final String name;
    private final Type type;

    CelPolicyVariable(final String name, final Type type) {
        this.name = name;
        this.type = type;
    }

    String variableName() {
        return name;
    }

    Decl declaration() {
        return Decls.newVar(name, type);
    }

}
