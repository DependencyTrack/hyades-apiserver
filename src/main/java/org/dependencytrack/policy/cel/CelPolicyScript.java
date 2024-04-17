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

import com.google.api.expr.v1alpha1.Type;
import org.apache.commons.collections4.MultiValuedMap;
import org.projectnessie.cel.Program;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.common.types.ref.Val;
import org.projectnessie.cel.tools.ScriptExecutionException;

import java.util.Map;

public class CelPolicyScript {

    private final Program program;
    private final MultiValuedMap<Type, String> requirements;

    CelPolicyScript(final Program program, final MultiValuedMap<Type, String> requirements) {
        this.program = program;
        this.requirements = requirements;
    }

    MultiValuedMap<Type, String> getRequirements() {
        return requirements;
    }

    boolean execute(final Map<String, Object> arguments) throws ScriptExecutionException {
        final Val result = program.eval(arguments).getVal();

        if (Err.isError(result)) {
            final Err error = (Err) result;
            throw new ScriptExecutionException(error.toString(), error.getCause());
        }

        return result.convertToNative(Boolean.class);
    }

}
