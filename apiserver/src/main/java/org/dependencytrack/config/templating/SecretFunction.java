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
package org.dependencytrack.config.templating;

import io.pebbletemplates.pebble.error.PebbleException;
import io.pebbletemplates.pebble.extension.Function;
import io.pebbletemplates.pebble.template.EvaluationContext;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

/**
 * @since 5.7.0
 */
final class SecretFunction implements Function {

    private static final String ARGUMENT_NAME = "name";

    private final java.util.function.Function<String, @Nullable String> secretResolver;

    SecretFunction(java.util.function.Function<String, @Nullable String> secretResolver) {
        this.secretResolver = secretResolver;
    }

    @Override
    public @Nullable Object execute(
            Map<String, Object> args,
            PebbleTemplate self,
            EvaluationContext context,
            int lineNumber) {
        final Object nameArgument = args.get(ARGUMENT_NAME);
        if (nameArgument == null) {
            throw new PebbleException(
                    null, "Missing argument: " + ARGUMENT_NAME, lineNumber, self.getName());
        }
        if (!(nameArgument instanceof final String name)) {
            throw new PebbleException(
                    null,
                    "Argument %s must be of type String, but was: %s".formatted(
                            ARGUMENT_NAME, nameArgument.getClass().getSimpleName()),
                    lineNumber,
                    self.getName());
        }

        return secretResolver.apply(name);
    }

    @Override
    public List<String> getArgumentNames() {
        return List.of(ARGUMENT_NAME);
    }

}
