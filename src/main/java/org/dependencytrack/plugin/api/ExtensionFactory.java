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

import java.io.Closeable;

/**
 * @since 5.6.0
 */
public interface ExtensionFactory<T extends ExtensionPoint> extends Closeable {

    int PRIORITY_HIGHEST = 0;
    int PRIORITY_LOWEST = Integer.MAX_VALUE;

    /**
     * @return Name of the extension. Can contain lowercase letters, numbers, and periods.
     */
    String extensionName();

    /**
     * @return {@link Class} of the extension.
     */
    Class<? extends T> extensionClass();

    /**
     * @return Priority of the extension. Must be a value between {@value #PRIORITY_HIGHEST}
     * (highest priority) and {@value #PRIORITY_LOWEST} (lowest priority).
     */
    int priority();

    /**
     * Initialize the factory. This method is called <em>once</em> during application startup.
     *
     * @param configRegistry A {@link ConfigRegistry} to read configuration from.
     */
    void init(final ConfigRegistry configRegistry);

    /**
     * @return An extension instance.
     */
    T create();

    /**
     * {@inheritDoc}
     */
    @Override
    default void close() {
        // Default no-op to remove checked exception from method signature.
    }

}
