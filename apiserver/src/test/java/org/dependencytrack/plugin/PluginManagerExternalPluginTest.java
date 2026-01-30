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

import org.dependencytrack.PersistenceCapableTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class PluginManagerExternalPluginTest extends PersistenceCapableTest {

    private PluginManager pluginManager;

    // Source code for external plugin
    private static final String TEST_PLUGIN_SOURCE = """
        package org.dependencytrack.plugin;
        
        import org.dependencytrack.plugin.api.ExtensionFactory;
        import org.dependencytrack.plugin.api.ExtensionPoint;
        import org.dependencytrack.plugin.api.Plugin;
        import java.util.Collection;
        
        public class MyExternalPlugin implements Plugin {
            @Override
            public Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
                return java.util.Collections.emptyList();
            }
        }
        """;

    @Before
    @Override
    public void before() throws Exception {
        super.before();
        pluginManager = PluginManager.getInstance();
        pluginManager.unloadPlugins();
    }

    @After
    @Override
    public void after() {
        pluginManager.unloadPlugins();
        super.after();
    }

    @Test
    public void shouldNotLoadExternalPluginsWhenDisabled() throws Exception {
        Path tempDir = Files.createTempDirectory("plugins");
        TestPluginJarBuilder.buildTestPluginJar(tempDir, "MyExternalPlugin", TEST_PLUGIN_SOURCE);

        pluginManager.setExternalPluginConfig(false, tempDir.toString());
        pluginManager.loadPlugins();

        assertThat(pluginManager.getLoadedPlugins())
                .noneMatch(p -> p.getClass().getSimpleName().equals("MyExternalPlugin"));
    }

    @Test
    public void shouldLoadExternalPluginWhenEnabled() throws Exception {
        Path tempDir = Files.createTempDirectory("plugins");
        TestPluginJarBuilder.buildTestPluginJar(tempDir, "MyExternalPlugin", TEST_PLUGIN_SOURCE);

        // Enable external plugins
        pluginManager.setExternalPluginConfig(true, tempDir.toString());
        pluginManager.loadPlugins();

        // Verify the plugin was loaded
        assertThat(pluginManager.getLoadedPlugins())
                .anyMatch(p -> p.getClass().getSimpleName().equals("MyExternalPlugin"));

        var plugin = pluginManager.getLoadedPlugins().stream()
                .filter(p -> p.getClass().getSimpleName().equals("MyExternalPlugin"))
                .findFirst()
                .orElseThrow();

        // Verify the plugin classloader is isolated
        assertThat(plugin.getClass().getClassLoader()).isInstanceOf(PluginIsolatedClassLoader.class);
    }
}
