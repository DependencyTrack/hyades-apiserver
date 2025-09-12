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

import alpine.model.ConfigProperty;
import alpine.model.IConfigProperty.PropertyType;
import alpine.security.crypto.DataEncryption;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.DeploymentConfigDefinition;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.util.DebugDataEncryption;
import org.eclipse.microprofile.config.ConfigProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.6.0
 */
public final class ConfigRegistryImpl implements ConfigRegistry {

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
    public static ConfigRegistryImpl forExtension(final String extensionPointName, final String extensionName) {
        return new ConfigRegistryImpl(requireNonNull(extensionPointName), requireNonNull(extensionName));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public void createWithDefaultsIfNotExist(final Collection<RuntimeConfigDefinition<?>> configs) {
        requireNonNull(extensionName, "extensionName must not be null");

        if (configs == null || configs.isEmpty()) {
            return;
        }

        final var configPropertiesToCreate = new ArrayList<ConfigProperty>(configs.size());
        for (final RuntimeConfigDefinition config : configs) {
            final Map.Entry<String, String> groupAndName = namespacedConfigGroupAndName(config);
            final String groupName = groupAndName.getKey();
            final String propertyName = groupAndName.getValue();

            final String valueString = config.type().toString(config.defaultValue());
            final String valueToStore;

            if (config.isSecret() && valueString != null) {
                try {
                    valueToStore = DataEncryption.encryptAsString(valueString);
                } catch (Exception e) {
                    throw new IllegalStateException(
                            "Failed to encrypt value of config %s".formatted(config.name()), e);
                }
            } else {
                valueToStore = valueString;
            }

            final var configProperty = new ConfigProperty();
            configProperty.setGroupName(groupName);
            configProperty.setPropertyName(propertyName);
            configProperty.setPropertyType(
                    config.isSecret()
                            ? PropertyType.ENCRYPTEDSTRING
                            : PropertyType.STRING);
            configProperty.setDescription(config.description());
            configProperty.setPropertyValue(valueToStore);
            configPropertiesToCreate.add(configProperty);
        }

        useJdbiTransaction(handle -> handle.attach(
                ConfigPropertyDao.class).maybeCreateAll(configPropertiesToCreate));
    }

    @Override
    public <T> Optional<T> getOptionalValue(final ConfigDefinition<T> config) {
        return switch (config) {
            case DeploymentConfigDefinition<T> it -> getDeploymentConfigValue(it);
            case RuntimeConfigDefinition<T> it -> getRuntimeConfigValue(it);
            case null -> throw new NullPointerException("config must not be null");
        };
    }

    @Override
    public <T> void setValue(final RuntimeConfigDefinition<T> config, final T value) {
        requireNonNull(config, "config must not be null");

        if (config.isRequired() && value == null) {
            throw new IllegalArgumentException(
                    "Config %s is defined as required, but value is null".formatted(config.name()));
        }

        final Map.Entry<String, String> groupAndName = namespacedConfigGroupAndName(config);
        final String groupName = groupAndName.getKey();
        final String propertyName = groupAndName.getValue();

        final String valueString = config.type().toString(value);
        final String valueToStore;
        if (config.isSecret() && value != null) {
            try {
                valueToStore = DataEncryption.encryptAsString(valueString);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to encrypt value of config %s".formatted(config.name()), e);
            }
        } else {
            valueToStore = valueString;
        }

        useJdbiTransaction(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);

            final boolean updated = dao.setValue(groupName, propertyName, valueToStore);
            if (!updated) {
                throw new NoSuchElementException("Config %s does not exist".formatted(config.name()));
            }
        });
    }

    private <T> Optional<T> getDeploymentConfigValue(final DeploymentConfigDefinition<T> config) {
        final String value = ConfigProvider.getConfig().getOptionalValue(
                namespacedConfigName(config), String.class).orElse(null);
        if (value == null) {
            if (config.isRequired()) {
                throw new IllegalStateException("""
                        Config %s is defined as required, but no value has been found\
                        """.formatted(config.name()));
            }

            return Optional.empty();
        }

        return Optional.of(config.type().fromString(value));
    }

    private <T> Optional<T> getRuntimeConfigValue(final RuntimeConfigDefinition<T> config) {
        final Map.Entry<String, String> groupAndName = namespacedConfigGroupAndName(config);
        final String groupName = groupAndName.getKey();
        final String propertyName = groupAndName.getValue();

        final ConfigProperty property = withJdbiHandle(
                handle -> handle.attach(ConfigPropertyDao.class).getOptional(groupName, propertyName)).orElse(null);
        if (property == null || property.getPropertyValue() == null) {
            if (config.isRequired()) {
                throw new IllegalStateException("""
                        Config %s is defined as required, but no value has been found\
                        """.formatted(config.name()));
            }

            return Optional.empty();
        }

        if (!config.isSecret()) {
            final T value = config.type().fromString(property.getPropertyValue());
            return Optional.of(value);
        }

        final boolean isEncrypted = property.getPropertyType() == PropertyType.ENCRYPTEDSTRING;
        if (!isEncrypted) {
            throw new IllegalStateException("""
                    Config %s is defined as secret, but its value is not encrypted\
                    """.formatted(config.name()));
        }

        try {
            final String decryptedValue = DebugDataEncryption.decryptAsString(property.getPropertyValue());
            final T value = config.type().fromString(decryptedValue);
            return Optional.of(value);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt value of config %s".formatted(config.name()), e);
        }
    }

    private String namespacedConfigName(final DeploymentConfigDefinition<?> config) {
        if (extensionName == null) {
            return "%s.%s".formatted(extensionPointName, config.name());
        }

        return "%s.extension.%s.%s".formatted(extensionPointName, extensionName, config.name());
    }

    private Map.Entry<String, String> namespacedConfigGroupAndName(final RuntimeConfigDefinition<?> config) {
        if (extensionName == null) {
            return Map.entry(extensionPointName, config.name());
        }

        return Map.entry(extensionPointName, "extension.%s.%s".formatted(extensionName, config.name()));
    }

}
