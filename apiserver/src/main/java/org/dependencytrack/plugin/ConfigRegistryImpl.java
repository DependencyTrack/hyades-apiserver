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
import alpine.model.ConfigProperty;
import alpine.model.IConfigProperty.PropertyType;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.plugin.api.ConfigDefinition;
import org.dependencytrack.plugin.api.ConfigRegistry;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.util.DebugDataEncryption;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;

import java.util.Objects;
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

    private ConfigRegistryImpl(final String extensionPointName, final String extensionName) {
        this.extensionPointName = extensionPointName;
        this.extensionName = extensionName;
    }

    /**
     * Create a {@link ConfigRegistryImpl} for accessing extension point configuration.
     *
     * @param extensionPointName Name of the extension point.
     * @return A {@link ConfigRegistryImpl} scoped to {@code extensionPointName}.
     */
    static ConfigRegistryImpl forExtensionPoint(final String extensionPointName) {
        return new ConfigRegistryImpl(requireNonNull(extensionPointName), null);
    }

    /**
     * Create a {@link ConfigRegistryImpl} for accessing extension configuration.
     *
     * @param extensionPointName Name of the extension point.
     * @param extensionName      Name of the extension.
     * @return A {@link ConfigRegistryImpl} scoped to {@code extensionPointName} and {@code extensionName}.
     */
    static ConfigRegistryImpl forExtension(final String extensionPointName, final String extensionName) {
        return new ConfigRegistryImpl(requireNonNull(extensionPointName), Objects.requireNonNull(extensionName));
    }

    @Override
    public Optional<String> getOptionalValue(final ConfigDefinition config) {
        return switch (config.source()) {
            case DEPLOYMENT -> getDeploymentConfigValue(config);
            case RUNTIME -> getRuntimeConfigValue(config);
            case ANY -> getDeploymentConfigValue(config).or(() -> getRuntimeConfigValue(config));
            case null -> throw new IllegalArgumentException("No config source specified");
        };
    }

    private record DeploymentConfigKey(String name) implements Config.Key {

        @Override
        public String getPropertyName() {
            return name;
        }

        @Override
        public Object getDefaultValue() {
            return null;
        }

    }

    private Optional<String> getDeploymentConfigValue(final ConfigDefinition config) {
        final var key = new DeploymentConfigKey(namespacedDeploymentConfigName(config));

        final String value = Config.getInstance().getProperty(key);
        if (value == null) {
            if (config.isRequired()) {
                throw new IllegalStateException("""
                        Config %s is defined as required, but no value has been found\
                        """.formatted(config.name()));
            }

            return Optional.empty();
        }

        return Optional.of(value);
    }

    private Optional<String> getRuntimeConfigValue(final ConfigDefinition config) {
        final Pair<String, String> groupAndName = namespacedRuntimeConfigGroupAndName(config);
        final String groupName = groupAndName.getLeft();
        final String propertyName = groupAndName.getRight();

        final ConfigProperty property = withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "PROPERTYVALUE"
                             , "PROPERTYTYPE"
                          FROM "CONFIGPROPERTY"
                         WHERE "GROUPNAME" = :groupName
                           AND "PROPERTYNAME" = :propertyName
                        """)
                .bind("groupName", groupName)
                .bind("propertyName", propertyName)
                .map(BeanMapper.of(ConfigProperty.class))
                .findOne()
                .orElse(null));
        if (property == null || property.getPropertyValue() == null) {
            if (config.isRequired()) {
                throw new IllegalStateException("""
                        Config %s is defined as required, but no value has been found\
                        """.formatted(config.name()));
            }

            return Optional.empty();
        }

        if (!config.isSecret()) {
            return Optional.of(property.getPropertyValue());
        }

        final boolean isEncrypted = property.getPropertyType() == PropertyType.ENCRYPTEDSTRING;
        if (!isEncrypted) {
            throw new IllegalStateException("""
                    Config %s is defined as secret, but its value is not encrypted\
                    """.formatted(config.name()));
        }

        try {
            final String decryptedValue = DebugDataEncryption.decryptAsString(property.getPropertyValue());
            return Optional.of(decryptedValue);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt value of config %s".formatted(config.name()), e);
        }
    }

    private String namespacedDeploymentConfigName(final ConfigDefinition config) {
        if (extensionName == null) {
            return "%s.%s".formatted(extensionPointName, config.name());
        }

        return "%s.extension.%s.%s".formatted(extensionPointName, extensionName, config.name());
    }

    private Pair<String, String> namespacedRuntimeConfigGroupAndName(final ConfigDefinition config) {
        if (extensionName == null) {
            return Pair.of(extensionPointName, config.name());
        }

        return Pair.of(extensionPointName, "extension.%s.%s".formatted(extensionName, config.name()));
    }

}
