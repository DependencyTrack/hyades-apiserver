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

import alpine.Config;
import alpine.common.logging.Logger;
import org.dependencytrack.plugin.ConfigRegistry.DeploymentConfigKey;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import static org.dependencytrack.plugin.ProviderFactory.PRIORITY_HIGHEST;
import static org.dependencytrack.plugin.ProviderFactory.PRIORITY_LOWEST;

/**
 * @since 5.6.0
 */
public class PluginManager {

    private record ProviderIdentity(Class<? extends Provider> clazz, String name) {
    }

    private static final Logger LOGGER = Logger.getLogger(PluginManager.class);
    private static final Pattern PLUGIN_NAME_PATTERN = Pattern.compile("^[a-z0-9.]+$");
    private static final Pattern PROVIDER_NAME_PATTERN = PLUGIN_NAME_PATTERN;
    private static final String PROPERTY_PROVIDER_ENABLED = "enabled";
    private static final String PROPERTY_DEFAULT_PROVIDER = "default.provider";
    private static final PluginManager INSTANCE = new PluginManager();

    private final List<Plugin> loadedPlugins;
    private final Map<Class<? extends Provider>, Plugin> pluginByProviderClass;
    private final Map<Class<? extends Provider>, Set<String>> providerNamesByProviderClass;
    private final Map<ProviderIdentity, ProviderFactory<?>> factoryByProviderKey;
    private final Map<Class<? extends Provider>, ProviderFactory<?>> defaultFactoryByProviderClass;
    private final Comparator<ProviderFactory<?>> providerFactoryComparator;
    private final ReentrantLock lock;

    private PluginManager() {
        this.loadedPlugins = new ArrayList<>();
        this.pluginByProviderClass = new HashMap<>();
        this.providerNamesByProviderClass = new HashMap<>();
        this.factoryByProviderKey = new HashMap<>();
        this.defaultFactoryByProviderClass = new HashMap<>();
        this.providerFactoryComparator = Comparator
                .<ProviderFactory<?>>comparingInt(ProviderFactory::priority)
                .thenComparing(ProviderFactory::providerName);
        this.lock = new ReentrantLock();
    }

    public static PluginManager getInstance() {
        return INSTANCE;
    }

    public List<Plugin> getLoadedPlugins() {
        return List.copyOf(loadedPlugins);
    }

    @SuppressWarnings("unchecked")
    public <T extends Provider, U extends ProviderFactory<T>> U getFactory(final Class<T> providerClass) {
        final ProviderFactory<?> factory = defaultFactoryByProviderClass.get(providerClass);
        if (factory == null) {
            return null;
        }

        return (U) factory;
    }

    @SuppressWarnings("unchecked")
    public <T extends Provider, U extends ProviderFactory<T>> SortedSet<U> getFactories(final Class<T> providerClass) {
        final Set<String> providerNames = providerNamesByProviderClass.get(providerClass);
        if (providerNames == null) {
            return Collections.emptySortedSet();
        }

        final var factories = new TreeSet<U>(providerFactoryComparator);
        for (final String providerName : providerNames) {
            final var providerKey = new ProviderIdentity(providerClass, providerName);
            final ProviderFactory<?> factory = factoryByProviderKey.get(providerKey);
            if (factory != null) {
                factories.add((U) factory);
            }
        }

        return factories;
    }

    void loadPlugins() {
        lock.lock();
        try {
            if (!loadedPlugins.isEmpty()) {
                // NB: This is primarily to prevent erroneous redundant calls to loadPlugins.
                // Under normal circumstances, this method will be called once on application
                // startup, making this very unlikely to happen.
                throw new IllegalStateException("Plugins were already loaded; Unload them first");
            }

            loadPluginsLocked();
        } finally {
            lock.unlock();
        }
    }

    private void loadPluginsLocked() {
        assert lock.isHeldByCurrentThread() : "Lock is not held by current thread";

        LOGGER.debug("Discovering plugins");
        final var pluginServiceLoader = ServiceLoader.load(Plugin.class);
        for (final Plugin plugin : pluginServiceLoader) {
            if (!PLUGIN_NAME_PATTERN.matcher(plugin.name()).matches()) {
                throw new IllegalStateException("%s is not a valid plugin name".formatted(plugin.name()));
            }

            loadProvidersForPlugin(plugin);

            LOGGER.debug("Loaded plugin %s".formatted(plugin.name()));
            loadedPlugins.add(plugin);
        }

        determineDefaultProviders();

        assertRequiredPlugins();
    }

    private void loadProvidersForPlugin(final Plugin plugin) {
        LOGGER.debug("Discovering providers for plugin %s".formatted(plugin.name()));
        final ServiceLoader<? extends ProviderFactory<? extends Provider>> providerFactoryServiceLoader = ServiceLoader.load(plugin.providerFactoryClass());
        for (final ProviderFactory<? extends Provider> providerFactory : providerFactoryServiceLoader) {
            if (!PROVIDER_NAME_PATTERN.matcher(providerFactory.providerName()).matches()) {
                throw new IllegalStateException("%s is not a valid provider name".formatted(providerFactory.providerName()));
            }

            LOGGER.debug("Discovered provider %s for plugin %s".formatted(providerFactory.providerName(), plugin.name()));
            final var configRegistry = new ConfigRegistry(plugin.name(), providerFactory.providerName());
            final boolean isEnabled = configRegistry.getDeploymentProperty(PROPERTY_PROVIDER_ENABLED).map(Boolean::parseBoolean).orElse(true);
            if (!isEnabled) {
                LOGGER.debug("Provider %s for plugin %s is disabled; Skipping".formatted(providerFactory.providerName(), plugin.name()));
                continue;
            }

            if (providerFactory.priority() < PRIORITY_HIGHEST) {
                throw new IllegalStateException("""
                        Provider %s has an invalid priority of %d; \
                        Allowed range is [%d..%d] (highest to lowest priority)\
                        """.formatted(providerFactory.providerName(), providerFactory.priority(), PRIORITY_HIGHEST, PRIORITY_LOWEST)
                );
            }

            LOGGER.debug("Initializing provider %s for plugin %s".formatted(providerFactory.providerName(), plugin.name()));
            try {
                providerFactory.init(configRegistry);
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to initialize provider %s for plugin %s; Skipping".formatted(providerFactory.providerName(), plugin.name()), e);
                continue;
            }

            pluginByProviderClass.put(plugin.providerClass(), plugin);

            providerNamesByProviderClass.compute(plugin.providerClass(), (ignored, providerNames) -> {
                if (providerNames == null) {
                    return new HashSet<>(Set.of(providerFactory.providerName()));
                }

                providerNames.add(providerFactory.providerName());
                return providerNames;
            });

            final var providerIdentity = new ProviderIdentity(plugin.providerClass(), providerFactory.providerName());
            factoryByProviderKey.put(providerIdentity, providerFactory);
        }
    }

    private void determineDefaultProviders() {
        for (final Class<? extends Provider> providerClass : providerNamesByProviderClass.keySet()) {
            final SortedSet<? extends ProviderFactory<?>> factories = getFactories(providerClass);
            if (factories == null || factories.isEmpty()) {
                LOGGER.debug("No factories available for provider class %s; Skipping".formatted(providerClass.getName()));
                continue;
            }

            final Plugin plugin = pluginByProviderClass.get(providerClass);
            if (plugin == null) {
                throw new IllegalStateException("""
                        No plugin exists for provider class %s; \
                        This is likely a logic error in the plugin loading procedure\
                        """.formatted(providerClass));
            }

            final ProviderFactory<?> providerFactory;
            final var defaultProviderConfigKey = new DeploymentConfigKey(plugin.name(), PROPERTY_DEFAULT_PROVIDER);
            final String providerName = Config.getInstance().getProperty(defaultProviderConfigKey);
            if (providerName == null) {
                LOGGER.debug("""
                        No default provider configured for plugin %s; \
                        Choosing based on priority""".formatted(plugin.name()));
                providerFactory = factories.first();
                LOGGER.debug("Chose provider %s with priority %d for plugin %s"
                        .formatted(providerFactory.providerName(), providerFactory.priority(), plugin.name()));
            } else {
                LOGGER.debug("Using configured default provider %s for plugin %s".formatted(providerName, plugin.name()));
                providerFactory = factories.stream()
                        .filter(factory -> factory.providerName().equals(providerName))
                        .findFirst()
                        .orElseThrow(() -> new NoSuchElementException("""
                                No provider named %s exists for plugin %s\
                                """.formatted(providerName, plugin.name())));
            }

            defaultFactoryByProviderClass.put(providerClass, providerFactory);
        }
    }

    private void assertRequiredPlugins() {
        for (final Plugin plugin : loadedPlugins) {
            if (!plugin.required()) {
                continue;
            }

            if (getFactory(plugin.providerClass()) == null) {
                throw new IllegalStateException("Plugin %s is required, but no provider is active".formatted(plugin.name()));
            }
        }
    }

    void unloadPlugins() {
        lock.lock();
        try {
            unloadPluginsLocked();
            defaultFactoryByProviderClass.clear();
            factoryByProviderKey.clear();
            providerNamesByProviderClass.clear();
            pluginByProviderClass.clear();
            loadedPlugins.clear();
        } finally {
            lock.unlock();
        }
    }

    private void unloadPluginsLocked() {
        assert lock.isHeldByCurrentThread() : "Lock is not held by current thread";

        for (final Plugin plugin : loadedPlugins) {
            LOGGER.debug("Closing providers for plugin %s".formatted(plugin.name()));

            for (ProviderFactory<?> providerFactory : getFactories(plugin.providerClass())) {
                LOGGER.debug("Closing provider %s for plugin %s".formatted(providerFactory.providerName(), plugin.name()));

                try {
                    providerFactory.close();
                } catch (RuntimeException e) {
                    LOGGER.warn("Failed to close provider %s for plugin %s".formatted(providerFactory.providerName(), plugin.name()), e);
                }
            }

            LOGGER.debug("Unloaded plugin %s".formatted(plugin.name()));
        }
    }

}
