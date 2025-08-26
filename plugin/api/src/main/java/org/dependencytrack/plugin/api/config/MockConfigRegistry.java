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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * @since 5.7.0
 */
public final class MockConfigRegistry implements ConfigRegistry {

    private final Map<String, String> properties;

    public MockConfigRegistry() {
        this(new HashMap<>());
    }

    public MockConfigRegistry(final Map<String, String> properties) {
        this.properties = properties;
    }

    @Override
    public Optional<String> getOptionalValue(final ConfigDefinition config) {
        return Optional.ofNullable(properties.get(config.name()));
    }

    @Override
    public void setValue(final RuntimeConfigDefinition config, final String value) {
        properties.put(config.name(), value);
    }

}