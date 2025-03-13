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
package org.dependencytrack.cache;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.github.resilience4j.cache.Cache;
import io.micrometer.core.instrument.binder.cache.JCacheMetrics;
import org.dependencytrack.common.ConfigKey;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import javax.cache.Caching;
import javax.cache.spi.CachingProvider;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.NoSuchElementException;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * @since 5.6.0
 */
public class CacheManager implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(CacheManager.class);

    private static final ReadWriteLock LOCK = new ReentrantReadWriteLock();
    private static javax.cache.CacheManager jCacheManager;

    private static javax.cache.CacheManager getjCacheManager() {
        LOCK.readLock().lock();
        try {
            if (jCacheManager == null) {
                LOCK.readLock().unlock();

                LOCK.writeLock().lock();
                try {
                    if (jCacheManager == null) {
                        jCacheManager = createJCacheManager();
                    }

                    LOCK.readLock().lock();
                } finally {
                    LOCK.writeLock().unlock();
                }
            }

            return jCacheManager;
        } finally {
            LOCK.readLock().unlock();
        }
    }

    public static void tearDown() {
        LOCK.readLock().lock();
        try {
            if (jCacheManager != null) {
                LOCK.readLock().unlock();

                LOCK.writeLock().lock();
                try {
                    if (jCacheManager != null) {
                        jCacheManager.close();
                        jCacheManager = null;
                    }

                    LOCK.readLock().lock();
                } finally {
                    LOCK.writeLock().unlock();
                }
            }
        } finally {
            LOCK.readLock().unlock();
        }
    }

    public static <K, V> Cache<K, V> getCache(final String cacheName) {
        final javax.cache.Cache<K, V> jCache = getjCacheManager().getCache(cacheName);
        if (jCache == null) {
            throw new NoSuchElementException();
        }

        return Cache.of(jCache);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public static void invalidateKeys(final String cacheName, final Collection<Object> keys) {
        final javax.cache.Cache jCache = jCacheManager.getCache(cacheName);
        if (jCache == null) {
            LOGGER.warn("Cache with name %s does not exist".formatted(cacheName));
            return;
        }

        if (keys == null) {
            LOGGER.debug("Invalidating all keys in cache " + cacheName);
            jCache.removeAll();
        } else {
            LOGGER.debug("Invalidating %d keys in cache %s".formatted(keys.size(), cacheName));
            jCache.removeAll(Set.copyOf(keys));
        }
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        javax.cache.CacheManager ignored = getjCacheManager();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        tearDown();
    }

    private static javax.cache.CacheManager createJCacheManager() {
        final String cacheProviderClassName = Config.getInstance().getProperty(ConfigKey.CACHE_PROVIDER);
        final CachingProvider cachingProvider = Caching.getCachingProvider(cacheProviderClassName);

        final javax.cache.CacheManager jCacheManager;
        final String cacheConfigFilePath = Config.getInstance().getProperty(ConfigKey.CACHE_CONFIG_FILE);
        if (cacheConfigFilePath != null) {
            LOGGER.debug("Loading cache configuration from " + cacheConfigFilePath);
            jCacheManager = cachingProvider.getCacheManager(Paths.get(cacheConfigFilePath).toUri(), null);
        } else {
            jCacheManager = cachingProvider.getCacheManager();
        }

        for (final CacheInitializer initializer : ServiceLoader.load(CacheInitializer.class)) {
            LOGGER.debug("Invoking cache initializer: " + initializer.getClass().getName());
            initializer.initializeCache(jCacheManager);
        }

        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            for (final String cacheName : jCacheManager.getCacheNames()) {
                jCacheManager.enableStatistics(cacheName, true);
                final javax.cache.Cache<?, ?> jCache = jCacheManager.getCache(cacheName);
                new JCacheMetrics<>(jCache, null).bindTo(Metrics.getRegistry());
            }
        }

        return jCacheManager;
    }

}
