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
 * @since 5.7.0
 */
public final class RuntimeConfigSpec {

    private final Class<? extends RuntimeConfig> configClass;
    private final RuntimeConfig defaultConfig;
    private final String configSchema;

    public RuntimeConfigSpec(
            RuntimeConfig defaultConfig,
            RuntimeConfigSchemaSource configSchemaSource) {
        this.defaultConfig = requireNonNull(defaultConfig, "defaultConfig must not be null");
        this.configClass = defaultConfig.getClass();
        requireNonNull(configSchemaSource, "configSchemaSource must not be null");
        this.configSchema = requireNonNull(configSchemaSource.getSchema(configClass), "configSchema must not be null");
    }

    public RuntimeConfigSpec(RuntimeConfig defaultConfig) {
        this(defaultConfig, new RuntimeConfigSchemaSource.Resource("runtime-config.schema.json"));
    }

    public Class<? extends RuntimeConfig> configClass() {
        return configClass;
    }

    public RuntimeConfig defaultConfig() {
        return defaultConfig;
    }

    public String schema() {
        return configSchema;
    }

}
