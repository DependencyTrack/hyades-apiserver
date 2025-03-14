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

import alpine.model.IConfigProperty;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.storage.FileStoragePlugin;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.util.List;
import java.util.SortedSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class PluginManagerTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    interface UnknownExtensionPoint extends ExtensionPoint {
    }

    @Test
    public void testGetLoadedPlugins() {
        final List<Plugin> loadedPlugins = PluginManager.getInstance().getLoadedPlugins();
        assertThat(loadedPlugins).satisfiesExactlyInAnyOrder(
                plugin -> assertThat(plugin).isOfAnyClassIn(DummyPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(FileStoragePlugin.class));
        assertThat(loadedPlugins).isUnmodifiable();
    }

    @Test
    public void testGetExtension() {
        final TestExtensionPoint extension =
                PluginManager.getInstance().getExtension(TestExtensionPoint.class);
        assertThat(extension).isNotNull();
        assertThat(extension.test()).isEqualTo("null-null");
    }

    @Test
    public void testGetExtensionWithConfig() {
        qm.createConfigProperty(
                /* groupName */ "test",
                /* propertyName */ "extension.dummy.foo",
                /* propertyValue */ "baz",
                IConfigProperty.PropertyType.STRING,
                /* description */ null
        );

        environmentVariables.set("TEST_EXTENSION_DUMMY_BAR", "qux");

        final TestExtensionPoint extension =
                PluginManager.getInstance().getExtension(TestExtensionPoint.class);
        assertThat(extension).isNotNull();
        assertThat(extension.test()).isEqualTo("baz-qux");
    }

    @Test
    public void testGetExtensionWithImplementationClass() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> PluginManager.getInstance().getExtension(DummyTestExtension.class))
                .withMessage("""
                        No extension exists for the extension point \
                        org.dependencytrack.plugin.DummyTestExtension""");
    }

    @Test
    public void testGetExtensionByName() {
        final TestExtensionPoint extension =
                PluginManager.getInstance().getExtension(TestExtensionPoint.class, "dummy");
        assertThat(extension).isNotNull();
    }

    @Test
    public void testGetExtensionByNameWhenNoExists() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> PluginManager.getInstance().getExtension(TestExtensionPoint.class, "doesNotExist"))
                .withMessage("""
                        No extension named doesNotExist exists for the extension point \
                        org.dependencytrack.plugin.TestExtensionPoint""");
    }

    @Test
    public void testGetFactory() {
        final ExtensionFactory<TestExtensionPoint> factory =
                PluginManager.getInstance().getFactory(TestExtensionPoint.class);
        assertThat(factory).isExactlyInstanceOf(DummyTestExtensionFactory.class);
    }

    @Test
    public void testGetFactoryForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> PluginManager.getInstance().getFactory(UnknownExtensionPoint.class))
                .withMessage("""
                        No extension factory exists for the extension point \
                        org.dependencytrack.plugin.PluginManagerTest$UnknownExtensionPoint""");
    }

    @Test
    public void testGetFactories() {
        final SortedSet<ExtensionFactory<TestExtensionPoint>> factories =
                PluginManager.getInstance().getFactories(TestExtensionPoint.class);
        assertThat(factories).satisfiesExactly(factory ->
                assertThat(factory).isExactlyInstanceOf(DummyTestExtensionFactory.class));
    }

    @Test
    public void testGetFactoriesForUnknownExtensionPoint() {
        final SortedSet<ExtensionFactory<UnknownExtensionPoint>> factories =
                PluginManager.getInstance().getFactories(UnknownExtensionPoint.class);
        assertThat(factories).isEmpty();
    }

    @Test
    public void testLoadPluginsRepeatedly() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> PluginManager.getInstance().loadPlugins())
                .withMessage("Plugins were already loaded; Unload them first");
    }

    @Test
    public void testDisabledExtension() {
        final PluginManager pluginManager = PluginManager.getInstance();

        pluginManager.unloadPlugins();

        environmentVariables.set("TEST_EXTENSION_DUMMY_ENABLED", "false");

        pluginManager.loadPlugins();

        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> PluginManager.getInstance().getExtension(TestExtensionPoint.class))
                .withMessage("""
                        No extension exists for the extension point \
                        org.dependencytrack.plugin.TestExtensionPoint""");
    }

    @Test
    public void testDefaultExtensionNotLoaded() {
        final PluginManager pluginManager = PluginManager.getInstance();

        pluginManager.unloadPlugins();

        environmentVariables.set("TEST_DEFAULT_EXTENSION", "does.not.exist");

        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(pluginManager::loadPlugins)
                .withMessage("""
                        No extension named does.not.exist exists for extension point \
                        test (org.dependencytrack.plugin.TestExtensionPoint)""");
    }

}