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
package org.dependencytrack.plugin;

import org.dependencytrack.common.config.NamespacedConfig;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.NonNull;

import java.util.Optional;

/**
 * @since 5.7.0
 */
final class NamespacedDelegatingDeploymentConfig implements DeploymentConfig {

    private final Config delegate;

    public NamespacedDelegatingDeploymentConfig(
            final Config delegate,
            final String extensionPointName,
            final String extensionName) {
        this.delegate = new NamespacedConfig(
                delegate, "%s.extension.%s".formatted(extensionPointName, extensionName));
    }

    @Override
    public <T> @NonNull T getValue(
            final @NonNull String propertyName,
            final @NonNull Class<T> propertyType) {
        return delegate.getValue(propertyName, propertyType);
    }

    @Override
    public <T> @NonNull Optional<T> getOptionalValue(
            final @NonNull String propertyName,
            final @NonNull Class<T> propertyType) {
        return delegate.getOptionalValue(propertyName, propertyType);
    }

}
