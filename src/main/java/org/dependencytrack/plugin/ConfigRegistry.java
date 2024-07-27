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

import alpine.Config;

import java.util.Optional;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * A read-only registry for accessing application configuration.
 * <p>
 * The registry enforces namespacing of property names,
 * to prevent {@link Provider}s from accessing values
 * belonging to the core application, or other plugins.
 * <p>
 * Namespacing is based on the plugin's, and the provider's name.
 * Provider {@code foo} of plugin {@code bar} can access:
 * <ul>
 *     <li>Runtime properties with {@code groupName} of {@code plugin} and {@code propertyName} starting with {@code bar.provider.foo}</li>
 *     <li>Deployment properties prefix {@code bar.provider.foo}</li>
 * </ul>
 * <p>
 * Runtime properties are sourced from the {@code CONFIGPROPERTY} database table.
 * Deployment properties are sourced from environment variables, and the {@code application.properties} file.
 *
 * @since 5.6.0
 */
public class ConfigRegistry {

    private final String pluginName;
    private final String providerName;

    public ConfigRegistry(final String pluginName, final String providerName) {
        this.pluginName = requireNonNull(pluginName);
        this.providerName = requireNonNull(providerName);
    }

    /**
     * @param propertyName Name of the runtime property.
     * @return An {@link Optional} holding the property value, or {@link Optional#empty()}.
     */
    public Optional<String> getRuntimeProperty(final String propertyName) {
        final String namespacedPropertyName = "%s.provider.%s.%s".formatted(pluginName, providerName, propertyName);

        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "PROPERTYVALUE"
                          FROM "CONFIGPROPERTY"
                         WHERE "GROUPNAME" = 'plugin'
                           AND "PROPERTYNAME" = :propertyName
                        """)
                .bind("propertyName", namespacedPropertyName)
                .mapTo(String.class)
                .findOne());
    }

    /**
     * @param propertyName Name of the deployment property.
     * @return An {@link Optional} holding the property value, or {@link Optional#empty()}.
     */
    public Optional<String> getDeploymentProperty(final String propertyName) {
        final var key = new DeploymentConfigKey(pluginName, providerName, propertyName);
        return Optional.ofNullable(Config.getInstance().getProperty(key));
    }

    record DeploymentConfigKey(String pluginName, String providerName, String name) implements Config.Key {

        DeploymentConfigKey(final String pluginName, final String name) {
            this(pluginName, null, name);
        }

        @Override
        public String getPropertyName() {
            if (providerName == null) {
                return "%s.%s".formatted(pluginName, name);
            }

            return "%s.provider.%s.%s".formatted(pluginName, providerName, name);
        }

        @Override
        public Object getDefaultValue() {
            return null;
        }

    }

}
