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
import org.dependencytrack.PersistenceCapableTest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class ConfigRegistryTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Test
    public void testGetRuntimeProperty() {
        qm.createConfigProperty(
                /* groupName */ "foo",
                /* propertyName */ "extension.bar.baz",
                /* propertyValue */ "qux",
                PropertyType.STRING,
                /* description */ null
        );

        final var configRegistry = new ConfigRegistry("foo", "bar");
        final Optional<String> optionalProperty = configRegistry.getRuntimeProperty("baz");
        assertThat(optionalProperty).contains("qux");
    }

    @Test
    public void testGetRuntimePropertyThatDoesNotExist() {
        final var configRegistry = new ConfigRegistry("foo", "bar");
        final Optional<String> optionalProperty = configRegistry.getRuntimeProperty("baz");
        assertThat(optionalProperty).isNotPresent();
    }

    @Test
    public void testDeploymentProperty() {
        environmentVariables.set("FOO_EXTENSION_BAR_BAZ", "qux");
        final var configRegistry = new ConfigRegistry("foo", "bar");
        final Optional<String> optionalProperty = configRegistry.getDeploymentProperty("baz");
        assertThat(optionalProperty).contains("qux");
    }

    @Test
    public void testDeploymentPropertyThatDoesNotExist() {
        final var configRegistry = new ConfigRegistry("foo", "bar");
        final Optional<String> optionalProperty = configRegistry.getDeploymentProperty("baz");
        assertThat(optionalProperty).isNotPresent();
    }

}