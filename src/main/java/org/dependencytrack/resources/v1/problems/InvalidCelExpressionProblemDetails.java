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
package org.dependencytrack.resources.v1.problems;

import io.swagger.v3.oas.annotations.Parameter;
import org.projectnessie.cel.Issues;

import java.util.List;

/**
 * @since 5.5.0
 */
public class InvalidCelExpressionProblemDetails extends ProblemDetails {

    public record CelExpressionError(
            @Parameter(description = "The line in which the error was identified") Integer line,
            @Parameter(description = "The column in which the error was identified") Integer column,
            @Parameter(description = "The message describing the error") String message
    ) {
    }

    @Parameter(description = "Errors identified during expression compilation")
    private final List<CelExpressionError> errors;

    public InvalidCelExpressionProblemDetails(final Issues issues) {
        this.errors = issues.getErrors().stream()
                .map(error -> new CelExpressionError(
                        error.getLocation().line(),
                        error.getLocation().column(),
                        error.getMessage()
                ))
                .toList();
    }

    public List<CelExpressionError> getErrors() {
        return errors;
    }

}
