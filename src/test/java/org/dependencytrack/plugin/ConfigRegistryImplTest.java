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

import alpine.model.IConfigProperty.PropertyType;
import alpine.security.crypto.DataEncryption;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.plugin.api.ConfigDefinition;
import org.dependencytrack.plugin.api.ConfigRegistry;
import org.dependencytrack.plugin.api.ConfigSource;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ConfigRegistryImplTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Test
    public void testGetRuntimeConfigValue() {
        qm.createConfigProperty(
                /* groupName */ "foo",
                /* propertyName */ "extension.bar.baz",
                /* propertyValue */ "qux",
                PropertyType.STRING,
                /* description */ null
        );

        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.RUNTIME, false, false);
        final Optional<String> optionalProperty = configRegistry.getOptionalValue(configDef);
        assertThat(optionalProperty).contains("qux");
    }

    @Test
    public void testGetRuntimeConfigValueThatDoesNotExist() {
        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.RUNTIME, false, false);
        final Optional<String> optionalProperty = configRegistry.getOptionalValue(configDef);
        assertThat(optionalProperty).isNotPresent();
    }

    @Test
    public void testGetRequiredRuntimeConfigValueThatDoesNotExist() {
        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.RUNTIME, true, false);
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> configRegistry.getOptionalValue(configDef))
                .withMessage("Config baz is defined as required, but no value has been found");
    }

    @Test
    public void testGetSecretRuntimeConfig() throws Exception {
        qm.createConfigProperty(
                /* groupName */ "foo",
                /* propertyName */ "extension.bar.baz",
                /* propertyValue */ DataEncryption.encryptAsString("qux"),
                PropertyType.ENCRYPTEDSTRING,
                /* description */ null
        );

        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.RUNTIME, false, true);
        final Optional<String> optionalProperty = configRegistry.getOptionalValue(configDef);
        assertThat(optionalProperty).contains("qux");
    }

    @Test
    public void testGetSecretRuntimeConfigWhenNotEncrypted() {
        qm.createConfigProperty(
                /* groupName */ "foo",
                /* propertyName */ "extension.bar.baz",
                /* propertyValue */ "qux",
                PropertyType.STRING,
                /* description */ null
        );

        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.RUNTIME, false, true);
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> configRegistry.getOptionalValue(configDef))
                .withMessage("Config baz is defined as secret, but its value is not encrypted");
    }

    @Test
    public void testDeploymentProperty() {
        environmentVariables.set("FOO_EXTENSION_BAR_BAZ", "qux");
        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.DEPLOYMENT, false, false);
        final Optional<String> optionalProperty = configRegistry.getOptionalValue(configDef);
        assertThat(optionalProperty).contains("qux");
    }

    @Test
    public void testDeploymentPropertyThatDoesNotExist() {
        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.DEPLOYMENT, false, false);
        final Optional<String> optionalProperty = configRegistry.getOptionalValue(configDef);
        assertThat(optionalProperty).isNotPresent();
    }

    @Test
    public void testGetRequiredDeploymentConfigValueThatDoesNotExist() {
        final ConfigRegistry configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        final var configDef = new ConfigDefinition("baz", ConfigSource.DEPLOYMENT, true, false);
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> configRegistry.getOptionalValue(configDef))
                .withMessage("Config baz is defined as required, but no value has been found");
    }

}