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
package org.dependencytrack.caching;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.ServletContext;
import org.dependencytrack.caching.api.CacheProvider;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public final class CacheProviderBinder extends AbstractBinder {

    @Override
    protected void configure() {
        bindFactory(CacheProviderFactory.class)
                .to(CacheProvider.class)
                .in(Singleton.class);
    }

    private static final class CacheProviderFactory implements Factory<CacheProvider> {

        private final ServletContext servletContext;

        @Inject
        private CacheProviderFactory(ServletContext servletContext) {
            this.servletContext = servletContext;
        }

        @Override
        public CacheProvider provide() {
            final var instance = (CacheProvider) servletContext.getAttribute(CacheProvider.class.getName());
            return requireNonNull(instance, "cacheProvider is not initialized");
        }

        @Override
        public void dispose(CacheProvider instance) {
            // Lifecycle is managed by CacheProviderInitializer.
        }

    }

}
