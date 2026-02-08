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
package org.dependencytrack.cache.local;

import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.cache.api.CacheProvider;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @since 5.7.0
 */
final class LocalCacheProvider implements CacheProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalCacheProvider.class);

    private final Config config;
    private final MeterRegistry meterRegistry;
    private final Map<String, Cache<?>> cacheByName;

    LocalCacheProvider(Config config, MeterRegistry meterRegistry) {
        this.config = config;
        this.meterRegistry = meterRegistry;
        this.cacheByName = new ConcurrentHashMap<>();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V> Cache<V> getCache(String name, Class<V> valueClass) {
        return (Cache<V>) cacheByName.computeIfAbsent(name, this::createCache);
    }

    @Override
    public @Nullable Cache<?> getCache(String name) {
        return cacheByName.get(name);
    }

    @Override
    public void close() {
        cacheByName.values().forEach(Cache::invalidateAll);
        cacheByName.clear();
    }

    private <V> Cache<V> createCache(String name) {
        LOGGER.debug("Creating cache {}", name);

        final Caffeine<Object, Object> caffeineCacheBuilder =
                Caffeine.newBuilder()
                        .recordStats();

        config.getOptionalValue("dt.cache.%s.max-size".formatted(name), long.class)
                .ifPresent(caffeineCacheBuilder::maximumSize);
        config.getOptionalValue("dt.cache.%s.ttl-ms".formatted(name), long.class)
                .map(Duration::ofMillis)
                .ifPresent(caffeineCacheBuilder::expireAfterWrite);

        final com.github.benmanes.caffeine.cache.Cache<String, Optional<V>> caffeineCache =
                caffeineCacheBuilder.build();

        new CaffeineCacheMetrics<>(caffeineCache, name, null)
                .bindTo(meterRegistry);

        return new LocalCache<>(caffeineCache);
    }

}
