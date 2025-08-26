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

import alpine.common.logging.Logger;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.DeploymentConfigDefinition;
import org.slf4j.MDC;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SequencedCollection;
import java.util.SequencedMap;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import static org.dependencytrack.common.MdcKeys.MDC_EXTENSION;
import static org.dependencytrack.common.MdcKeys.MDC_EXTENSION_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_EXTENSION_POINT;
import static org.dependencytrack.common.MdcKeys.MDC_EXTENSION_POINT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PLUGIN;
import static org.dependencytrack.plugin.api.ExtensionFactory.PRIORITY_HIGHEST;
import static org.dependencytrack.plugin.api.ExtensionFactory.PRIORITY_LOWEST;

/**
 * @since 5.6.0
 */
public class PluginManager {

    private static final Logger LOGGER = Logger.getLogger(PluginManager.class);
    private static final Pattern EXTENSION_POINT_NAME_PATTERN = Pattern.compile("^[a-z0-9.]+$");
    private static final Pattern EXTENSION_NAME_PATTERN = EXTENSION_POINT_NAME_PATTERN;
    private static final ConfigDefinition<Boolean> CONFIG_EXTENSION_ENABLED =
            new DeploymentConfigDefinition<>("enabled", ConfigTypes.BOOLEAN, /* isRequired */ false);
    private static final ConfigDefinition<String> CONFIG_DEFAULT_EXTENSION =
            new DeploymentConfigDefinition<>("default.extension", ConfigTypes.STRING, /* isRequired */ false);
    private static final PluginManager INSTANCE = new PluginManager();

    private final SequencedMap<Class<? extends Plugin>, Plugin> loadedPluginByClass;
    private final Map<ExtensionIdentity, Plugin> pluginByExtensionIdentity;
    private final Map<Plugin, List<ExtensionFactory<?>>> factoriesByPlugin;
    private final Map<Class<? extends ExtensionPoint>, ExtensionPointSpec<?>> specByExtensionPointClass;
    private final Map<Class<? extends ExtensionPoint>, Set<String>> extensionNamesByExtensionPointClass;
    private final Map<ExtensionIdentity, ExtensionFactory<?>> factoryByExtensionIdentity;
    private final Map<Class<? extends ExtensionPoint>, ExtensionFactory<?>> defaultFactoryByExtensionPointClass;
    private final Comparator<ExtensionFactory<?>> factoryComparator;
    private final ReentrantLock lock;

    private PluginManager() {
        this.loadedPluginByClass = new LinkedHashMap<>();
        this.pluginByExtensionIdentity = new HashMap<>();
        this.factoriesByPlugin = new HashMap<>();
        this.specByExtensionPointClass = new HashMap<>();
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

    public SequencedCollection<ExtensionPointSpec<?>> getExtensionPoints() {
        return List.copyOf(specByExtensionPointClass.values());
    }

    public SequencedCollection<Plugin> getLoadedPlugins() {
        return List.copyOf(loadedPluginByClass.sequencedValues());
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint> T getExtension(final Class<T> extensionPointClass) {
        final ExtensionFactory<?> factory = defaultFactoryByExtensionPointClass.get(extensionPointClass);
        if (factory == null) {
            throw new NoSuchExtensionException(
                    "No extension exists for the extension point " + extensionPointClass.getName());
        }

        return (T) factory.create();
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint> T getExtension(final Class<T> extensionPointClass, final String name) {
        final var extensionIdentity = new ExtensionIdentity(extensionPointClass, name);
        final ExtensionFactory<?> factory = factoryByExtensionIdentity.get(extensionIdentity);
        if (factory == null) {
            throw new NoSuchExtensionException(
                    "No extension named %s exists for the extension point %s".formatted(
                            name, extensionPointClass.getName()));
        }

        return (T) factory.create();
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint, U extends ExtensionFactory<T>> U getFactory(final Class<T> extensionPointClass) {
        final ExtensionFactory<?> factory = defaultFactoryByExtensionPointClass.get(extensionPointClass);
        if (factory == null) {
            throw new NoSuchExtensionException(
                    "No extension factory exists for the extension point " + extensionPointClass.getName());
        }

        return (U) factory;
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint, U extends ExtensionFactory<T>> SequencedCollection<U> getFactories(final Class<T> extensionPointClass) {
        final Set<String> extensionNames = extensionNamesByExtensionPointClass.get(extensionPointClass);
        if (extensionNames == null) {
            return Collections.emptyList();
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
            if (!loadedPluginByClass.isEmpty()) {
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
        final var extensionPointSpecLoader = ServiceLoader.load(ExtensionPointSpec.class);
        for (final ExtensionPointSpec<?> spec : extensionPointSpecLoader) {
            if (!EXTENSION_POINT_NAME_PATTERN.matcher(spec.name()).matches()) {
                throw new IllegalStateException(
                        "%s is not a valid extension point name".formatted(spec.name()));
            }

            LOGGER.debug("Discovered extension point %s".formatted(spec.name()));
            specByExtensionPointClass.put(spec.extensionPointClass(), spec);
        }

        LOGGER.debug("Discovering plugins");
        final var pluginLoader = ServiceLoader.load(Plugin.class);
        for (final Plugin plugin : pluginLoader) {
            try (var ignoredMdcPlugin = MDC.putCloseable(MDC_PLUGIN, plugin.getClass().getName())) {
                LOGGER.debug("Loading plugin");
                loadExtensionsForPlugin(plugin);

                LOGGER.debug("Plugin loaded successfully");
                loadedPluginByClass.put(plugin.getClass(), plugin);
            }
        }

        determineDefaultExtensions();

        assertRequiredExtensionPoints();
    }

    private void loadExtensionsForPlugin(final Plugin plugin) {
        final Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories = plugin.extensionFactories();
        if (extensionFactories == null || extensionFactories.isEmpty()) {
            LOGGER.debug("Plugin does not define any extensions; Skipping");
            return;
        }

        for (final ExtensionFactory<? extends ExtensionPoint> extensionFactory : extensionFactories) {
            if (extensionFactory.extensionName() == null) {
                throw new IllegalStateException(
                        "%s does not define an extension name".formatted(
                                extensionFactory.getClass().getName()));
            }
            if (!EXTENSION_NAME_PATTERN.matcher(extensionFactory.extensionName()).matches()) {
                throw new IllegalStateException(
                        "%s defines an invalid extension name: %s".formatted(
                                extensionFactory.getClass().getName(), extensionFactory.extensionName()));
            }
            if (extensionFactory.extensionClass() == null) {
                throw new IllegalStateException(
                        "%s does not define an extension class".formatted(
                                extensionFactory.getClass().getName()));
            }

            // Prevent plugins from registering their extensions as non-concrete classes.
            // The purpose of tracking extension classes is to differentiate them from another,
            // which would be impossible if we allowed interfaces or abstract classes.
            if (extensionFactory.extensionClass().isInterface()
                || Modifier.isAbstract(extensionFactory.extensionClass().getModifiers())) {
                throw new IllegalStateException("""
                        Class %s of extension %s from plugin %s is either abstract or an interface; \
                        Extension classes must be concrete""".formatted(extensionFactory.extensionClass().getName(),
                        extensionFactory.extensionName(), MDC.get(MDC_PLUGIN)));
            }

            final ExtensionPointSpec<?> extensionPointSpec =
                    requireKnownExtensionPoint(extensionFactory.extensionClass());

            try (var ignored = new MdcScope(Map.ofEntries(
                    Map.entry(MDC_EXTENSION_POINT_NAME, extensionPointSpec.name()),
                    Map.entry(MDC_EXTENSION_POINT, extensionPointSpec.extensionPointClass().getName()),
                    Map.entry(MDC_EXTENSION_NAME, extensionFactory.extensionName()),
                    Map.entry(MDC_EXTENSION, extensionFactory.extensionClass().getName())))) {
                loadExtension(plugin, extensionFactory, extensionPointSpec);
            }
        }
    }

    private void loadExtension(
            final Plugin plugin,
            final ExtensionFactory<? extends ExtensionPoint> extensionFactory,
            final ExtensionPointSpec<?> extensionPointSpec) {
        final var extensionIdentity = new ExtensionIdentity(
                extensionPointSpec.extensionPointClass(),
                extensionFactory.extensionName());

        // Prevent the same extension from being loaded from multiple plugins.
        if (pluginByExtensionIdentity.containsKey(extensionIdentity)) {
            final Plugin conflictingPlugin = pluginByExtensionIdentity.get(extensionIdentity);
            throw new IllegalStateException(
                    "Extension was already loaded from plugin %s".formatted(
                            conflictingPlugin.getClass().getName()));
        }

        final var configRegistry = ConfigRegistryImpl.forExtension(extensionPointSpec.name(), extensionIdentity.name());
        final boolean isEnabled = configRegistry.getOptionalValue(CONFIG_EXTENSION_ENABLED).orElse(true);
        if (!isEnabled) {
            LOGGER.debug("Extension is disabled; Skipping");
            return;
        }

        if (extensionFactory.priority() < PRIORITY_HIGHEST) {
            throw new IllegalStateException("""
                    Extension %s from plugin %s has an invalid priority of %d; \
                    Allowed range is [%d..%d] (highest to lowest priority)\
                    """.formatted(MDC.get(MDC_EXTENSION), MDC.get(MDC_PLUGIN),
                    extensionFactory.priority(), PRIORITY_HIGHEST, PRIORITY_LOWEST)
            );
        }

        LOGGER.debug("Creating runtime extension configs with defaults if necessary");
        configRegistry.createWithDefaultsIfNotExist(extensionFactory.runtimeConfigs());

        LOGGER.debug("Initializing extension");
        try {
            extensionFactory.init(configRegistry);
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "Failed to initialize extension %s from plugin %s".formatted(
                            MDC.get(MDC_EXTENSION), MDC.get(MDC_PLUGIN)), e);
        }

        factoriesByPlugin.computeIfAbsent(
                        plugin, ignored -> new ArrayList<>())
                .add(extensionFactory);
        extensionNamesByExtensionPointClass.computeIfAbsent(
                        extensionIdentity.extensionPointClass(),
                        ignored -> new HashSet<>())
                .add(extensionFactory.extensionName());
        factoryByExtensionIdentity.put(extensionIdentity, extensionFactory);
        pluginByExtensionIdentity.put(extensionIdentity, plugin);
    }

    private void determineDefaultExtensions() {
        for (final Class<? extends ExtensionPoint> extensionPointClass : extensionNamesByExtensionPointClass.keySet()) {
            final ExtensionPointSpec<?> extensionPointSpec = specByExtensionPointClass.get(extensionPointClass);
            if (extensionPointSpec == null) {
                throw new IllegalStateException("""
                        No specification exists for extension point %s; \
                        This is likely a logic error in the plugin loading procedure\
                        """.formatted(extensionPointClass.getName()));
            }

            try (var ignored = new MdcScope(Map.ofEntries(
                    Map.entry(MDC_EXTENSION_POINT, extensionPointClass.getName()),
                    Map.entry(MDC_EXTENSION_POINT_NAME, extensionPointSpec.name())))) {
                LOGGER.debug("Determining default extension");

                final SequencedCollection<? extends ExtensionFactory<?>> factories = getFactories(extensionPointClass);
                if (factories == null || factories.isEmpty()) {
                    LOGGER.warn("No extension available; Skipping");
                    continue;
                }

                final var configRegistry = ConfigRegistryImpl.forExtensionPoint(extensionPointSpec.name());
                final Optional<String> defaultExtensionName = configRegistry.getOptionalValue(CONFIG_DEFAULT_EXTENSION);

                final ExtensionFactory<?> extensionFactory;
                if (defaultExtensionName.isEmpty()) {
                    LOGGER.debug("No default extension configured; Choosing based on priority");
                    extensionFactory = factories.getFirst();
                    LOGGER.debug("Chose extension %s (%s) with priority %d as default".formatted(
                            extensionFactory.extensionName(),
                            extensionFactory.extensionClass().getName(),
                            extensionFactory.priority()));
                } else {
                    extensionFactory = factories.stream()
                            .filter(factory -> factory.extensionName().equals(defaultExtensionName.get()))
                            .findFirst()
                            .orElseThrow(() -> new NoSuchExtensionException("""
                                    No extension named %s exists for extension point %s (%s)"""
                                    .formatted(defaultExtensionName.get(), MDC.get(MDC_EXTENSION_POINT_NAME), MDC.get(MDC_EXTENSION_POINT))));
                    LOGGER.debug("Using extension %s (%s) as default".formatted(
                            extensionFactory.extensionName(), extensionFactory.extensionClass().getName()));
                }

                defaultFactoryByExtensionPointClass.put(extensionPointClass, extensionFactory);
            }
        }
    }

    private ExtensionPointSpec<?> requireKnownExtensionPoint(final Class<? extends ExtensionPoint> concreteExtensionClass) {
        for (final Class<? extends ExtensionPoint> extensionPointClass : specByExtensionPointClass.keySet()) {
            if (extensionPointClass.isAssignableFrom(concreteExtensionClass)) {
                return specByExtensionPointClass.get(extensionPointClass);
            }
        }

        throw new IllegalStateException(
                "Extension %s does not implement any known extension point".formatted(
                        concreteExtensionClass.getName()));
    }

    private void assertRequiredExtensionPoints() {
        for (final ExtensionPointSpec<?> spec : specByExtensionPointClass.values()) {
            if (!spec.required()) {
                continue;
            }

            if (getFactory(spec.extensionPointClass()) == null) {
                throw new IllegalStateException(
                        "Extension point %s (%s) is required, but no extension is enabled".formatted(
                                spec.name(), spec.extensionPointClass().getName()));
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
            specByExtensionPointClass.clear();
            factoriesByPlugin.clear();
            pluginByExtensionIdentity.clear();
            loadedPluginByClass.clear();
        } finally {
            lock.unlock();
        }
    }

    private void unloadPluginsLocked() {
        assert lock.isHeldByCurrentThread() : "Lock is not held by current thread";

        // Unload plugins in reverse order in which they were loaded.
        for (final Plugin plugin : loadedPluginByClass.sequencedValues().reversed()) {
            try (var ignoredMdcPlugin = MDC.putCloseable(MDC_PLUGIN, plugin.getClass().getName())) {
                LOGGER.debug("Unloading plugin");
                unloadPlugin(plugin);

                LOGGER.debug("Plugin unloaded");
            }
        }
    }

    private void unloadPlugin(final Plugin plugin) {
        final List<ExtensionFactory<?>> factories = factoriesByPlugin.get(plugin);
        if (factories == null || factories.isEmpty()) {
            LOGGER.debug("No extensions were loaded; Skipping");
            return;
        }

        // Close factories in reverse order in which they were initialized.
        for (final ExtensionFactory<?> extensionFactory : factories.reversed()) {
            final ExtensionPointSpec<?> extensionPointSpec = requireKnownExtensionPoint(extensionFactory.extensionClass());

            final String extensionPointClassName = extensionPointSpec.extensionPointClass().getName();
            final String extensionClassName = extensionFactory.extensionClass().getName();

            try (var ignoredMdcExtensionPoint = MDC.putCloseable(MDC_EXTENSION_POINT, extensionPointClassName);
                 var ignoredMdcExtension = MDC.putCloseable(MDC_EXTENSION, extensionClassName)) {
                LOGGER.debug("Closing extension");
                extensionFactory.close();

                LOGGER.debug("Extension closed successfully");
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to close extension", e);
            }
        }
    }

}
