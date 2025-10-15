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
package org.dependencytrack.plugin.api.config;

import static java.util.Objects.requireNonNull;

/**
 * Definition of a runtime configuration.
 * <p>
 * Configurations of this type are mutable and may be changed by users and / or extensions
 * while the application is running.
 *
 * @param name          Name of the config.
 * @param description   Description of the config.
 * @param type          Type of the config.
 * @param defaultValue  Default value of the config.
 * @param isRequired    Whether the config is required (value must not be {@code null}).
 * @param isSecret      Whether the config is secret (value should be stored in encrypted form).
 * @since 5.7.0
 */
public record RuntimeConfigDefinition<T>(
        String name,
        String description,
        ConfigType<T> type,
        T defaultValue,
        boolean isRequired,
        boolean isSecret) implements ConfigDefinition<T> {

    public RuntimeConfigDefinition {
        requireNonNull(name, "name must not be null");
        requireNonNull(description, "description must not be null");
        requireNonNull(type, "type must not be null");
    }

}
