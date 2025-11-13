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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class PluginManagerExternalPluginTest {

    private PluginManager pluginManager;

    private static final String TEST_PLUGIN_SOURCE = """
        package org.dependencytrack.plugin;
        public class MyExternalPlugin implements Plugin {
            @Override
            public String name() { return "External Test Plugin"; }
        }
        """;

    @BeforeEach
    void setUp() {
        pluginManager = PluginManager.getInstance();
        pluginManager.unloadPlugins();
    }

    @AfterEach
    void tearDown() {
        pluginManager.unloadPlugins();
    }

    @Test
    void shouldNotLoadExternalPluginsWhenDisabled() throws Exception {

        Path tempDir = Files.createTempDirectory("plugins");
        TestPluginJarBuilder.buildTestPluginJar(tempDir, "MyExternalPlugin", TEST_PLUGIN_SOURCE);

        pluginManager.setExternalPluginConfig(false, tempDir.toString());
        pluginManager.loadPlugins();

        assertThat(pluginManager.getLoadedPlugins())
                .noneMatch(p -> p.getClass().getSimpleName().equals("MyExternalPlugin"));
    }

    @Test
    void shouldLoadExternalPluginWhenEnabled() throws Exception {
        Path tempDir = Files.createTempDirectory("plugins");
        TestPluginJarBuilder.buildTestPluginJar(tempDir, "MyExternalPlugin", TEST_PLUGIN_SOURCE);

        pluginManager.setExternalPluginConfig(true, tempDir.toString());
        pluginManager.loadPlugins();

        assertThat(pluginManager.getLoadedPlugins())
                .anyMatch(p -> p.getClass().getSimpleName().equals("MyExternalPlugin"));

        var plugin = pluginManager.getLoadedPlugins().stream()
                .filter(p -> p.getClass().getSimpleName().equals("MyExternalPlugin"))
                .findFirst()
                .orElseThrow();

        assertThat(plugin.getClass().getClassLoader())
                .isInstanceOf(PluginIsolatedClassLoader.class);
    }
}
