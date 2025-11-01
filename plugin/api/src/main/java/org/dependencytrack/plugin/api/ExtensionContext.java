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
package org.dependencytrack.plugin.api;

import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.InMemoryExtensionKVStore;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;

import java.net.ProxySelector;
import java.util.Objects;

/**
 * @since 5.7.0
 */
public final class ExtensionContext {

    private final ConfigRegistry configRegistry;
    private final ExtensionKVStore keyValueStore;
    private final ProxySelector proxySelector;

    public ExtensionContext(
            final ConfigRegistry configRegistry,
            final ExtensionKVStore kvStore,
            final ProxySelector proxySelector) {
        this.configRegistry = Objects.requireNonNull(configRegistry, "configRegistry must not be null");
        this.keyValueStore = Objects.requireNonNull(kvStore, "kvStore must not be null");
        this.proxySelector = proxySelector != null ? proxySelector : ProxySelector.getDefault();
    }

    public ExtensionContext(final ConfigRegistry configRegistry) {
        this(configRegistry, new InMemoryExtensionKVStore(), null);
    }

    public ConfigRegistry configRegistry() {
        return configRegistry;
    }

    public ExtensionKVStore kvStore() {
        return keyValueStore;
    }

    public ProxySelector proxySelector() {
        return proxySelector;
    }

}
