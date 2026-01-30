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

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

/**
 * Child-first classloader with configurable shared package prefixes.
 */
public final class PluginIsolatedClassLoader extends URLClassLoader {

    private final ClassLoader hostClassLoader;
    private final List<String> sharedPackagePrefixes;

    /**
     * @param urls URLs pointing to plugin JAR(s).
     * @param hostClassLoader classloader to supply shared API classes.
     * @param sharedPackagePrefixes list of package prefixes that must be loaded from host.
     */
    public PluginIsolatedClassLoader(final URL[] urls, final ClassLoader hostClassLoader, final List<String> sharedPackagePrefixes) {
        super(urls, null);
        this.hostClassLoader = Objects.requireNonNull(hostClassLoader, "hostClassLoader");
        this.sharedPackagePrefixes = List.copyOf(Objects.requireNonNull(sharedPackagePrefixes, "sharedPackagePrefixes"));
    }

    private boolean isShared(final String className) {
        for (final String prefix : sharedPackagePrefixes) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected synchronized Class<?> loadClass(final String name, final boolean resolve) throws ClassNotFoundException {
        // delegate to host
        if (isShared(name)) {
            return hostClassLoader.loadClass(name);
        }

        Class<?> loaded = findLoadedClass(name);
        if (loaded != null) {
            if (resolve) {
                resolveClass(loaded);
            }
            return loaded;
        }

        // Try to load from plugin JAR
        try {
            Class<?> clazz = findClass(name);
            if (resolve) {
                resolveClass(clazz);
            }
            return clazz;
        } catch (ClassNotFoundException ignored) {
        }

        // Fallback to host classloader
        return hostClassLoader.loadClass(name);
    }

    @Override
    public URL getResource(final String name) {
        final String dotted = name.replace('/', '.');
        for (final String prefix : sharedPackagePrefixes) {
            if (dotted.startsWith(prefix)) {
                return hostClassLoader.getResource(name);
            }
        }

        final URL url = findResource(name);
        if (url != null) {
            return url;
        }
        return hostClassLoader.getResource(name);
    }

    @Override
    public Enumeration<URL> getResources(final String name) throws IOException {
        final Enumeration<URL> pluginResources = findResources(name);
        final Enumeration<URL> hostResources = hostClassLoader.getResources(name);

        return new Enumeration<>() {
            @Override
            public boolean hasMoreElements() {
                return pluginResources.hasMoreElements() || hostResources.hasMoreElements();
            }

            @Override
            public URL nextElement() {
                if (pluginResources.hasMoreElements()) {
                    return pluginResources.nextElement();
                }
                return hostResources.nextElement();
            }
        };
    }

    @Override
    public void close() throws IOException {
        super.close();
    }
}
