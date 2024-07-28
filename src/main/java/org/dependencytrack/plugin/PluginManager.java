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

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
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

import static org.dependencytrack.plugin.ExtensionFactory.PRIORITY_HIGHEST;
import static org.dependencytrack.plugin.ExtensionFactory.PRIORITY_LOWEST;

/**
 * @since 5.6.0
 */
public class PluginManager {

    private record ExtensionIdentity(Class<? extends ExtensionPoint> clazz, String name) {
    }

    private static final Logger LOGGER = Logger.getLogger(PluginManager.class);
    private static final Pattern PLUGIN_NAME_PATTERN = Pattern.compile("^[a-z0-9.]+$");
    private static final Pattern EXTENSION_POINT_NAME_PATTERN = PLUGIN_NAME_PATTERN;
    private static final Pattern EXTENSION_NAME_PATTERN = PLUGIN_NAME_PATTERN;
    private static final String PROPERTY_EXTENSION_ENABLED = "enabled";
    private static final String PROPERTY_DEFAULT_EXTENSION = "default.extension";
    private static final PluginManager INSTANCE = new PluginManager();

    private final List<Plugin> loadedPlugins;
    private final Map<Plugin, List<ExtensionFactory<?>>> factoriesByPlugin;
    private final Map<Class<? extends ExtensionPoint>, ExtensionPointMetadata<?>> metadataByExtensionPointClass;
    private final Map<Class<? extends ExtensionPoint>, Set<String>> extensionNamesByExtensionPointClass;
    private final Map<ExtensionIdentity, ExtensionFactory<?>> factoryByExtensionIdentity;
    private final Map<Class<? extends ExtensionPoint>, ExtensionFactory<?>> defaultFactoryByExtensionPointClass;
    private final Comparator<ExtensionFactory<?>> factoryComparator;
    private final ReentrantLock lock;

    private PluginManager() {
        this.loadedPlugins = new ArrayList<>();
        this.factoriesByPlugin = new HashMap<>();
        this.metadataByExtensionPointClass = new HashMap<>();
        this.extensionNamesByExtensionPointClass = new HashMap<>();
        this.factoryByExtensionIdentity = new HashMap<>();
        this.defaultFactoryByExtensionPointClass = new HashMap<>();
        this.factoryComparator = Comparator
                .<ExtensionFactory<?>>comparingInt(ExtensionFactory::priority)
                .thenComparing(ExtensionFactory::extensionName);
        this.lock = new ReentrantLock();
    }

    public static PluginManager getInstance() {
        return INSTANCE;
    }

    public List<Plugin> getLoadedPlugins() {
        return List.copyOf(loadedPlugins);
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint> T getExtension(final Class<T> extensionPointClass) {
        final ExtensionFactory<?> factory = defaultFactoryByExtensionPointClass.get(extensionPointClass);
        if (factory == null) {
            return null;
        }

        return (T) factory.create();
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint, U extends ExtensionFactory<T>> U getFactory(final Class<T> extensionPointClass) {
        final ExtensionFactory<?> factory = defaultFactoryByExtensionPointClass.get(extensionPointClass);
        if (factory == null) {
            return null;
        }

        return (U) factory;
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint, U extends ExtensionFactory<T>> SortedSet<U> getFactories(final Class<T> extensionPointClass) {
        final Set<String> extensionNames = extensionNamesByExtensionPointClass.get(extensionPointClass);
        if (extensionNames == null) {
            return Collections.emptySortedSet();
        }

        final var factories = new TreeSet<U>(factoryComparator);
        for (final String extensionName : extensionNames) {
            final var extensionIdentity = new ExtensionIdentity(extensionPointClass, extensionName);
            final ExtensionFactory<?> factory = factoryByExtensionIdentity.get(extensionIdentity);
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

        LOGGER.debug("Discovering extension points");
        final var extensionPointMetadataLoader = ServiceLoader.load(ExtensionPointMetadata.class);
        for (final ExtensionPointMetadata<?> metadata : extensionPointMetadataLoader) {
            if (!EXTENSION_POINT_NAME_PATTERN.matcher(metadata.name()).matches()) {
                throw new IllegalStateException("%s is not a valid extension point name".formatted(metadata.name()));
            }

            LOGGER.debug("Discovered extension point %s".formatted(metadata.name()));
            metadataByExtensionPointClass.put(metadata.extensionPointClass(), metadata);
        }

        LOGGER.debug("Discovering plugins");
        final var pluginLoader = ServiceLoader.load(Plugin.class);
        for (final Plugin plugin : pluginLoader) {
            if (!PLUGIN_NAME_PATTERN.matcher(plugin.name()).matches()) {
                throw new IllegalStateException("%s is not a valid plugin name".formatted(plugin.name()));
            }

            loadExtensionsForPlugin(plugin);

            LOGGER.info("Loaded plugin %s".formatted(plugin.name()));
            loadedPlugins.add(plugin);
        }

        determineDefaultExtensions();

        assertRequiredExtensionPoints();
    }

    private void loadExtensionsForPlugin(final Plugin plugin) {
        final Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories = plugin.extensionFactories();
        if (extensionFactories == null || extensionFactories.isEmpty()) {
            return;
        }

        LOGGER.debug("Discovering extensions for plugin %s".formatted(plugin.name()));
        for (final ExtensionFactory<? extends ExtensionPoint> extensionFactory : extensionFactories) {
            if (extensionFactory.extensionName() == null
                || !EXTENSION_NAME_PATTERN.matcher(extensionFactory.extensionName()).matches()) {
                throw new IllegalStateException("%s is not a valid extension name".formatted(extensionFactory.extensionName()));
            }

            if (extensionFactory.extensionClass() == null) {
                throw new IllegalStateException("Extension %s from plugin %s does not define an extension class"
                        .formatted(extensionFactory.extensionName(), plugin.name()));
            }

            // Prevent plugins from registering their extensions as non-concrete classes.
            // The purpose of tracking extension classes is to differentiate them from another,
            // which would be impossible if we allowed interfaces or abstract classes.
            if (extensionFactory.extensionClass().isInterface()
                || Modifier.isAbstract(extensionFactory.extensionClass().getModifiers())) {
                throw new IllegalStateException("""
                        Class %s of extension %s from plugin %s is either abstract or an interface; \
                        Extension classes must be concrete""".formatted(extensionFactory.extensionClass().getName(),
                        extensionFactory.extensionName(), plugin.name()));
            }

            final ExtensionPointMetadata<?> extensionPointMetadata =
                    assertKnownExtensionPoint(extensionFactory.extensionClass());

            LOGGER.debug("Discovered extension %s/%s from plugin %s"
                    .formatted(extensionPointMetadata.name(), extensionFactory.extensionName(), plugin.name()));
            final var configRegistry = new ConfigRegistry(extensionPointMetadata.name(), extensionFactory.extensionName());
            final boolean isEnabled = configRegistry.getDeploymentProperty(PROPERTY_EXTENSION_ENABLED).map(Boolean::parseBoolean).orElse(true);
            if (!isEnabled) {
                LOGGER.debug("Extension %s/%s from plugin %s is disabled; Skipping"
                        .formatted(extensionPointMetadata.name(), extensionFactory.extensionName(), plugin.name()));
                continue;
            }

            if (extensionFactory.priority() < PRIORITY_HIGHEST) {
                throw new IllegalStateException("""
                        Extension %s/%s from plugin %s has an invalid priority of %d; \
                        Allowed range is [%d..%d] (highest to lowest priority)\
                        """.formatted(extensionPointMetadata.name(), extensionFactory.extensionName(),
                        plugin.name(), extensionFactory.priority(), PRIORITY_HIGHEST, PRIORITY_LOWEST)
                );
            }

            LOGGER.info("Initializing extension %s/%s from plugin %s"
                    .formatted(extensionPointMetadata.name(), extensionFactory.extensionName(), plugin.name()));
            try {
                extensionFactory.init(configRegistry);
            } catch (RuntimeException e) {
                throw new IllegalStateException("Failed to initialize extension %s/%s from plugin %s"
                        .formatted(extensionPointMetadata.name(), extensionFactory.extensionName(), plugin.name()), e);
            }

            factoriesByPlugin.compute(plugin, (ignored, factories) -> {
                if (factories == null) {
                    return new ArrayList<>(List.of(extensionFactory));
                }

                factories.add(extensionFactory);
                return factories;
            });

            extensionNamesByExtensionPointClass.compute(
                    extensionPointMetadata.extensionPointClass(),
                    (ignored, extensionNames) -> {
                        if (extensionNames == null) {
                            return new HashSet<>(Set.of(extensionFactory.extensionName()));
                        }

                        extensionNames.add(extensionFactory.extensionName());
                        return extensionNames;
                    }
            );

            final var extensionIdentity = new ExtensionIdentity(
                    extensionPointMetadata.extensionPointClass(),
                    extensionFactory.extensionName()
            );
            factoryByExtensionIdentity.put(extensionIdentity, extensionFactory);
        }
    }

    private void determineDefaultExtensions() {
        for (final Class<? extends ExtensionPoint> extensionPointClass : extensionNamesByExtensionPointClass.keySet()) {
            final SortedSet<? extends ExtensionFactory<?>> factories = getFactories(extensionPointClass);
            if (factories == null || factories.isEmpty()) {
                LOGGER.debug("No factories available for extension point class %s; Skipping".formatted(extensionPointClass.getName()));
                continue;
            }

            final ExtensionPointMetadata<?> extensionPointMetadata = metadataByExtensionPointClass.get(extensionPointClass);
            if (extensionPointMetadata == null) {
                throw new IllegalStateException("""
                        No metadata exists for extension point class %s; \
                        This is likely a logic error in the plugin loading procedure\
                        """.formatted(extensionPointClass));
            }

            final ExtensionFactory<?> extensionFactory;
            final var defaultProviderConfigKey = new DeploymentConfigKey(extensionPointMetadata.name(), PROPERTY_DEFAULT_EXTENSION);
            final String defaultExtensionName = Config.getInstance().getProperty(defaultProviderConfigKey);
            if (defaultExtensionName == null) {
                LOGGER.warn("""
                        No default extension configured for extension point %s; \
                        Choosing based on priority""".formatted(extensionPointMetadata.name()));
                extensionFactory = factories.first();
                LOGGER.info("Chose extension %s with priority %d as default for extension point %s"
                        .formatted(extensionFactory.extensionName(), extensionFactory.priority(), extensionPointMetadata.name()));
            } else {
                LOGGER.info("Using configured default extension %s for extension point %s"
                        .formatted(defaultExtensionName, extensionPointMetadata.name()));
                extensionFactory = factories.stream()
                        .filter(factory -> factory.extensionName().equals(defaultExtensionName))
                        .findFirst()
                        .orElseThrow(() -> new NoSuchElementException("""
                                No extension named %s exists for extension point %s\
                                """.formatted(defaultExtensionName, extensionPointMetadata.name())));
            }

            defaultFactoryByExtensionPointClass.put(extensionPointClass, extensionFactory);
        }
    }

    private ExtensionPointMetadata<?> assertKnownExtensionPoint(final Class<? extends ExtensionPoint> concreteExtensionClass) {
        for (final Class<? extends ExtensionPoint> knownExtensionPoint : metadataByExtensionPointClass.keySet()) {
            if (knownExtensionPoint.isAssignableFrom(concreteExtensionClass)) {
                return metadataByExtensionPointClass.get(knownExtensionPoint);
            }
        }

        throw new IllegalStateException("Extension %s does not implement any known extension point"
                .formatted(concreteExtensionClass.getName()));
    }

    private void assertRequiredExtensionPoints() {
        for (final ExtensionPointMetadata<?> metadata : metadataByExtensionPointClass.values()) {
            if (!metadata.required()) {
                continue;
            }

            if (getFactory(metadata.extensionPointClass()) == null) {
                throw new IllegalStateException("Extension point %s is required, but no extension is active".formatted(metadata.name()));
            }
        }
    }

    void unloadPlugins() {
        lock.lock();
        try {
            unloadPluginsLocked();
            defaultFactoryByExtensionPointClass.clear();
            factoryByExtensionIdentity.clear();
            extensionNamesByExtensionPointClass.clear();
            metadataByExtensionPointClass.clear();
            loadedPlugins.clear();
        } finally {
            lock.unlock();
        }
    }

    private void unloadPluginsLocked() {
        assert lock.isHeldByCurrentThread() : "Lock is not held by current thread";

        // Unload plugins in reverse order in which they were loaded.
        for (final Plugin plugin : loadedPlugins.reversed()) {
            LOGGER.info("Unloading plugin %s".formatted(plugin.name()));

            final List<ExtensionFactory<?>> factories = factoriesByPlugin.get(plugin);
            if (factories == null || factories.isEmpty()) {
                LOGGER.debug("No extensions were loaded for plugin %s; Skipping".formatted(plugin.name()));
                continue;
            }

            // Close factories in reverse order in which they were initialized.
            for (final ExtensionFactory<?> extensionFactory : factories.reversed()) {
                final ExtensionPointMetadata<?> extensionPointMetadata =
                        assertKnownExtensionPoint(extensionFactory.extensionClass());

                LOGGER.info("Closing extension %s/%s for plugin %s"
                        .formatted(extensionPointMetadata.name(), extensionFactory.extensionName(), plugin.name()));

                try {
                    extensionFactory.close();
                } catch (RuntimeException e) {
                    LOGGER.warn("Failed to close extension %s/%s for plugin %s"
                            .formatted(extensionPointMetadata.name(), extensionFactory.extensionName(), plugin.name()), e);
                }
            }

            LOGGER.debug("Unloaded plugin %s".formatted(plugin.name()));
        }
    }

}
