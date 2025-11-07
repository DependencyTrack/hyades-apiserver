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

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Enumeration;
import java.util.Objects;

public class PluginIsolatedClassLoader extends URLClassLoader {

    private static final Logger LOGGER = Logger.getLogger(PluginIsolatedClassLoader.class);

    public PluginIsolatedClassLoader(URL[] urls, ClassLoader parent) {
        super(urls, Objects.requireNonNull(parent));
    }

    public PluginIsolatedClassLoader(URL[] urls) {
        super(urls, null);
    }

    @Override
    protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        Class<?> loadedClass = findLoadedClass(name);
        if (loadedClass != null) {
            if (resolve) {
                resolveClass(loadedClass);
            }
            return loadedClass;
        }

        // Load the class from the classloader (plugin JARs)
        try {
            loadedClass = findClass(name);
            if (resolve) {
                resolveClass(loadedClass);
            }
            return loadedClass;
        } catch (ClassNotFoundException ignored) {
            LOGGER.debug("Plugin not found: %s".formatted(name));
        }
        return super.loadClass(name, resolve);
    }

    @Override
    public URL getResource(String name) {
        // Look for plugin local resource first
        URL url = findResource(name);
        if (url != null) {
            return url;
        }
        return super.getResource(name);
    }

    @Override
    public Enumeration<URL> getResources(String name) throws IOException {

        // First priority to plugin resources over parent resources
        Enumeration<URL> pluginResources = findResources(name);
        Enumeration<URL> parentResources = getParent().getResources(name);

        return new Enumeration<>() {
            @Override
            public boolean hasMoreElements() {
                return pluginResources.hasMoreElements() || parentResources.hasMoreElements();
            }

            @Override
            public URL nextElement() {
                if (pluginResources.hasMoreElements()) {
                    return pluginResources.nextElement();
                }
                return parentResources.nextElement();
            }
        };
    }

    @Override
    public void close() throws IOException {
        super.close();
    }
}
