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
import org.dependencytrack.plugin.api.ConfigRegistry;
import org.dependencytrack.plugin.api.ExtensionPoint;

import java.util.Optional;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * A read-only registry for accessing application configuration.
 * <p>
 * The registry enforces namespacing of property names,
 * to prevent {@link ExtensionPoint}s from accessing values
 * belonging to the core application, or other extension points.
 * <p>
 * Namespacing is based on the extension point's, and the extension's name.
 * Extension {@code bar} of extension point {@code foo} can access:
 * <ul>
 *     <li>Runtime properties with {@code groupName} of {@code foo} and {@code propertyName} prefixed with {@code extension.bar}</li>
 *     <li>Deployment properties prefixed with {@code foo.extension.bar}</li>
 * </ul>
 * <p>
 * Runtime properties are sourced from the {@code CONFIGPROPERTY} database table.
 * Deployment properties are sourced from environment variables, and the {@code application.properties} file.
 *
 * @since 5.6.0
 */
class ConfigRegistryImpl implements ConfigRegistry {

    private final String extensionPointName;
    private final String extensionName;

    public ConfigRegistryImpl(final String extensionPointName, final String extensionName) {
        this.extensionPointName = requireNonNull(extensionPointName);
        this.extensionName = requireNonNull(extensionName);
    }

    @Override
    public Optional<String> getRuntimeProperty(final String propertyName) {
        final String namespacedPropertyName = "extension.%s.%s".formatted(extensionName, propertyName);

        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "PROPERTYVALUE"
                          FROM "CONFIGPROPERTY"
                         WHERE "GROUPNAME" = :extensionPointName
                           AND "PROPERTYNAME" = :propertyName
                        """)
                .bind("extensionPointName", extensionPointName)
                .bind("propertyName", namespacedPropertyName)
                .mapTo(String.class)
                .findOne());
    }

    @Override
    public Optional<String> getDeploymentProperty(final String propertyName) {
        final var key = new DeploymentConfigKey(extensionPointName, extensionName, propertyName);
        return Optional.ofNullable(Config.getInstance().getProperty(key));
    }

    record DeploymentConfigKey(String extensionPointName, String extensionName, String name) implements Config.Key {

        DeploymentConfigKey(final String extensionPointName, final String name) {
            this(extensionPointName, null, name);
        }

        @Override
        public String getPropertyName() {
            if (extensionName == null) {
                return "%s.%s".formatted(extensionPointName, name);
            }

            return "%s.extension.%s.%s".formatted(extensionPointName, extensionName, name);
        }

        @Override
        public Object getDefaultValue() {
            return null;
        }

    }

}
