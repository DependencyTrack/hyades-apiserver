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

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.SequencedCollection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class PluginManagerTest extends PersistenceCapableTest {

    interface UnknownExtensionPoint extends ExtensionPoint {
    }

    private PluginManager pluginManager;

    @BeforeEach
    void beforeEach() {
        pluginManager = new PluginManager(
                ConfigProvider.getConfig(),
                new NoopCacheManager(),
                secretName -> null,
                List.of(TestExtensionPoint.class));
        pluginManager.loadPlugins(List.of(new DummyPlugin()));
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void testGetLoadedPlugins() {
        final SequencedCollection<Plugin> loadedPlugins =
                pluginManager.getLoadedPlugins();
        assertThat(loadedPlugins).isNotEmpty();
        assertThat(loadedPlugins).isUnmodifiable();
    }

    @Test
    void testGetExtensionWithConfig() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.test.dummy.bar", "qux")
                .build();

        try (final var pluginManager = new PluginManager(
                config, new NoopCacheManager(), secretName -> null, List.of(TestExtensionPoint.class))) {
            pluginManager.loadPlugins(List.of(new DummyPlugin()));

            final TestExtensionPoint extension =
                    pluginManager.getExtension(TestExtensionPoint.class);
            assertThat(extension).isNotNull();
            assertThat(extension.test()).isEqualTo("qux");
        }
    }

    @Test
    void testGetExtensionWithImplementationClass() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> pluginManager.getExtension(DummyTestExtension.class))
                .withMessage("org.dependencytrack.plugin.DummyTestExtension is not a known extension point");
    }

    @Test
    void testGetExtensionByName() {
        final TestExtensionPoint extension =
                pluginManager.getExtension(TestExtensionPoint.class, "dummy");
        assertThat(extension).isNotNull();
    }

    @Test
    void testGetExtensionByNameWhenNoExists() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> pluginManager.getExtension(TestExtensionPoint.class, "doesNotExist"))
                .withMessage("No extension named 'doesNotExist' exists for the extension point 'test'");
    }

    @Test
    void testGetFactory() {
        final ExtensionFactory<TestExtensionPoint> factory =
                pluginManager.getFactory(TestExtensionPoint.class);
        assertThat(factory).isExactlyInstanceOf(DummyTestExtensionFactory.class);
    }

    @Test
    void testGetFactoryForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> pluginManager.getFactory(UnknownExtensionPoint.class))
                .withMessage("org.dependencytrack.plugin.PluginManagerTest$UnknownExtensionPoint is not a known extension point");
    }

    @Test
    void testGetFactories() {
        final SequencedCollection<ExtensionFactory<TestExtensionPoint>> factories =
                pluginManager.getFactories(TestExtensionPoint.class);
        assertThat(factories).satisfiesExactly(factory ->
                assertThat(factory).isExactlyInstanceOf(DummyTestExtensionFactory.class));
    }

    @Test
    void testGetFactoriesForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> pluginManager.getFactories(UnknownExtensionPoint.class));
    }

    @Test
    void testGetKVStore() {
        final ExtensionKVStore kvStore =
                pluginManager.getKVStore(TestExtensionPoint.class, "dummy");
        assertThat(kvStore).isInstanceOf(DatabaseExtensionKVStore.class);
    }

    @Test
    void testGetKVStoreForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> pluginManager.getKVStore(UnknownExtensionPoint.class, "dummy"));
    }

    @Test
    void testGetKVStoreForUnknownExtension() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> pluginManager.getKVStore(TestExtensionPoint.class, "doesNotExist"));
    }

    @Test
    void testLoadPluginsRepeatedly() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> pluginManager.loadPlugins(List.of(new DummyPlugin())))
                .withMessage("Plugins were already loaded; Unload them first");
    }

    @Test
    void testDisabledExtension() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.test.dummy.enabled", "false")
                .build();

        try (final var pluginManager = new PluginManager(
                config, new NoopCacheManager(), secretName -> null, List.of(TestExtensionPoint.class))) {
            pluginManager.loadPlugins(List.of(new DummyPlugin()));

            assertThatExceptionOfType(NoSuchExtensionException.class)
                    .isThrownBy(() -> pluginManager.getExtension(TestExtensionPoint.class))
                    .withMessage("No extension exists for the extension point 'test'");
        }
    }

    @Test
    void testDefaultExtensionNotLoaded() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.test.default-extension", "does.not.exist")
                .build();

        try (final var pluginManager = new PluginManager(
                config, new NoopCacheManager(), secretName -> null, List.of(TestExtensionPoint.class))) {
            assertThatExceptionOfType(NoSuchExtensionException.class)
                    .isThrownBy(() -> pluginManager.loadPlugins(List.of(new DummyPlugin())))
                    .withMessage("No extension named 'does.not.exist' exists for the extension point 'test'");
        }
    }

}