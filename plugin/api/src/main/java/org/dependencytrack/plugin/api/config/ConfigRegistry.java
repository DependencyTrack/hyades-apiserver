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

import org.dependencytrack.plugin.api.ExtensionPoint;
import org.jspecify.annotations.Nullable;

/**
 * A read-only registry for accessing application configuration.
 * <p>
 * The registry enforces namespacing of property names,
 * to prevent {@link ExtensionPoint}s from accessing values
 * belonging to the core application, or other extension points.
 * <p>
 * Namespacing is based on the extension point's, and the extension's name.
 *
 * @since 5.6.0
 */
public interface ConfigRegistry {

    /**
     * @since 5.7.0
     */
    DeploymentConfig getDeploymentConfig();

    /**
     * @since 5.7.0
     */
    @Nullable RuntimeConfig getRuntimeConfig();

    /**
     * @since 5.7.0
     */
    default <T extends RuntimeConfig> @Nullable T getRuntimeConfig(final Class<T> configClass) {
        return configClass.cast(getRuntimeConfig());
    }

}
