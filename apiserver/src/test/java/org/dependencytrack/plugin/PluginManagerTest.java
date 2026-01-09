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

import alpine.test.config.ConfigPropertyExtension;
import alpine.test.config.WithConfigProperty;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.SequencedCollection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class PluginManagerTest extends PersistenceCapableTest {

    interface UnknownExtensionPoint extends ExtensionPoint {
    }

    @RegisterExtension
    private static final ConfigPropertyExtension configProperties = new ConfigPropertyExtension();

    @BeforeEach
    void beforeEach() {
        PluginManagerTestUtil.loadPlugins();
    }

    @Test
    void testGetLoadedPlugins() {
        final SequencedCollection<Plugin> loadedPlugins =
                PluginManager.getInstance().getLoadedPlugins();
        assertThat(loadedPlugins).isNotEmpty();
        assertThat(loadedPlugins).isUnmodifiable();
    }

    @Test
    @WithConfigProperty("test.extension.dummy.bar=qux")
    void testGetExtensionWithConfig() {
        final TestExtensionPoint extension =
                PluginManager.getInstance().getExtension(TestExtensionPoint.class);
        assertThat(extension).isNotNull();
        assertThat(extension.test()).isEqualTo("qux");
    }

    @Test
    void testGetExtensionWithImplementationClass() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> PluginManager.getInstance().getExtension(DummyTestExtension.class))
                .withMessage("org.dependencytrack.plugin.DummyTestExtension is not a known extension point");
    }

    @Test
    void testGetExtensionByName() {
        final TestExtensionPoint extension =
                PluginManager.getInstance().getExtension(TestExtensionPoint.class, "dummy");
        assertThat(extension).isNotNull();
    }

    @Test
    void testGetExtensionByNameWhenNoExists() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> PluginManager.getInstance().getExtension(TestExtensionPoint.class, "doesNotExist"))
                .withMessage("No extension named 'doesNotExist' exists for the extension point 'test'");
    }

    @Test
    void testGetFactory() {
        final ExtensionFactory<TestExtensionPoint> factory =
                PluginManager.getInstance().getFactory(TestExtensionPoint.class);
        assertThat(factory).isExactlyInstanceOf(DummyTestExtensionFactory.class);
    }

    @Test
    void testGetFactoryForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> PluginManager.getInstance().getFactory(UnknownExtensionPoint.class))
                .withMessage("org.dependencytrack.plugin.PluginManagerTest$UnknownExtensionPoint is not a known extension point");
    }

    @Test
    void testGetFactories() {
        final SequencedCollection<ExtensionFactory<TestExtensionPoint>> factories =
                PluginManager.getInstance().getFactories(TestExtensionPoint.class);
        assertThat(factories).satisfiesExactly(factory ->
                assertThat(factory).isExactlyInstanceOf(DummyTestExtensionFactory.class));
    }

    @Test
    void testGetFactoriesForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> PluginManager.getInstance().getFactories(UnknownExtensionPoint.class));
    }

    @Test
    void testGetKVStore() {
        final ExtensionKVStore kvStore =
                PluginManager.getInstance().getKVStore(TestExtensionPoint.class, "dummy");
        assertThat(kvStore).isInstanceOf(DatabaseExtensionKVStore.class);
    }

    @Test
    void testGetKVStoreForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> PluginManager.getInstance().getKVStore(UnknownExtensionPoint.class, "dummy"));
    }

    @Test
    void testGetKVStoreForUnknownExtension() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> PluginManager.getInstance().getKVStore(TestExtensionPoint.class, "doesNotExist"));
    }

    @Test
    void testLoadPluginsRepeatedly() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> PluginManager.getInstance().loadPlugins())
                .withMessage("Plugins were already loaded; Unload them first");
    }

    @Test
    @WithConfigProperty("test.extension.dummy.enabled=false")
    void testDisabledExtension() {
        final PluginManager pluginManager = PluginManager.getInstance();

        pluginManager.unloadPlugins();

        pluginManager.loadPlugins();

        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> PluginManager.getInstance().getExtension(TestExtensionPoint.class))
                .withMessage("No extension exists for the extension point 'test'");
    }

    @Test
    void testDefaultExtensionNotLoaded() {
        final PluginManager pluginManager = PluginManager.getInstance();

        pluginManager.unloadPlugins();

        configProperties.setProperty("test.default.extension", "does.not.exist");

        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(pluginManager::loadPlugins)
                .withMessage("No extension named 'does.not.exist' exists for the extension point 'test'");
    }

}