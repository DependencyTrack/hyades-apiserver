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
import org.junit.Test;

import java.util.List;
import java.util.SortedSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class PluginManagerTest extends PersistenceCapableTest {

    interface InvalidProvider extends Provider {
    }

    @Test
    public void testGetLoadedPlugins() {
        final List<Plugin> loadedPlugins = PluginManager.getInstance().getLoadedPlugins();
        assertThat(loadedPlugins).hasSize(1);
        assertThat(loadedPlugins).isUnmodifiable();
    }

    @Test
    public void testGetFactory() {
        final ProviderFactory<DummyProvider> factory =
                PluginManager.getInstance().getFactory(DummyProvider.class);
        assertThat(factory).isNotNull();
    }

    @Test
    public void testGetFactoryForInvalidProvider() {
        final ProviderFactory<InvalidProvider> factory =
                PluginManager.getInstance().getFactory(InvalidProvider.class);
        assertThat(factory).isNull();
    }

    @Test
    public void testGetFactories() {
        final SortedSet<ProviderFactory<DummyProvider>> factories =
                PluginManager.getInstance().getFactories(DummyProvider.class);
        assertThat(factories).hasSize(1);
    }

    @Test
    public void testGetFactoriesForInvalidProvider() {
        final SortedSet<ProviderFactory<InvalidProvider>> factories =
                PluginManager.getInstance().getFactories(InvalidProvider.class);
        assertThat(factories).isEmpty();
    }

    @Test
    public void testLoadPluginsRepeatedly() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> PluginManager.getInstance().loadPlugins())
                .withMessage("Plugins were already loaded; Unload them first");
    }

}