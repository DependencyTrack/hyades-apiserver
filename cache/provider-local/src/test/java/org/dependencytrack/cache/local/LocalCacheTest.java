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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.cache.api.CacheProvider;
import org.dependencytrack.cache.api.CacheProviderFactory;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class LocalCacheTest {

    private CacheProviderFactory providerFactory;
    private CacheProvider provider;

    @BeforeEach
    void beforeEach() {
        final Config config = new SmallRyeConfigBuilder().build();
        providerFactory = new LocalCacheProviderFactory(config, new SimpleMeterRegistry());
        provider = providerFactory.create();
    }

    @AfterEach
    void afterEach() throws Exception {
        if (provider != null) {
            provider.close();
        }
    }

    @Nested
    class FactoryTest {

        @Test
        void shouldReturnLocalAsName() {
            assertThat(providerFactory.name()).isEqualTo("local");
        }

        @Test
        void shouldCreateNewProviderOnEachCall() {
            final CacheProvider anotherProvider = providerFactory.create();

            assertThat(anotherProvider).isNotSameAs(provider);
        }

    }

    @Nested
    class ProviderGetCacheWithClassTest {

        @Test
        void shouldCreateCache() {
            final Cache<String> cache = provider.getCache("test", String.class);

            assertThat(cache).isNotNull();
        }

        @Test
        void shouldReturnSameCacheForSameName() {
            final Cache<String> cache1 = provider.getCache("test", String.class);
            final Cache<String> cache2 = provider.getCache("test", String.class);

            assertThat(cache2).isSameAs(cache1);
        }

        @Test
        void shouldReturnDifferentCachesForDifferentNames() {
            final Cache<String> cache1 = provider.getCache("test1", String.class);
            final Cache<String> cache2 = provider.getCache("test2", String.class);

            assertThat(cache2).isNotSameAs(cache1);
        }

    }

    @Nested
    class ProviderGetCacheByNameTest {

        @Test
        void shouldReturnNullWhenCacheDoesNotExist() {
            assertThat(provider.getCache("nonExistent")).isNull();
        }

        @Test
        void shouldReturnExistingCache() {
            final Cache<String> created = provider.getCache("test", String.class);

            assertThat(provider.getCache("test")).isSameAs(created);
        }

    }

    @Nested
    class ProviderCloseTest {

        @Test
        void shouldInvalidateAllCachesOnClose() throws Exception {
            final Cache<String> cache = provider.getCache("test", String.class);
            cache.put("key", "value");

            provider.close();

            final CacheProvider newProvider = providerFactory.create();
            final Cache<String> newCache = newProvider.getCache("test", String.class);
            assertThat(newCache.get("key", k -> "newValue")).isEqualTo("newValue");
        }

        @Test
        void shouldClearCacheRegistryOnClose() throws Exception {
            provider.getCache("test", String.class);

            provider.close();

            assertThat(provider.getCache("test")).isNull();
        }

    }

    @Nested
    class CacheGetTest {

        @Test
        void shouldReturnValueFromLoader() {
            final Cache<String> cache = provider.getCache("test", String.class);

            final String result = cache.get("key", k -> "value");

            assertThat(result).isEqualTo("value");
        }

        @Test
        void shouldReturnCachedValueWithoutCallingLoader() {
            final Cache<String> cache = provider.getCache("test", String.class);
            cache.put("key", "cachedValue");
            final var loaderCallCount = new AtomicInteger(0);

            final String result = cache.get("key", k -> {
                loaderCallCount.incrementAndGet();
                return "loaderValue";
            });

            assertThat(result).isEqualTo("cachedValue");
            assertThat(loaderCallCount).hasValue(0);
        }

        @Test
        void shouldReturnNullWhenLoaderReturnsNull() {
            final Cache<String> cache = provider.getCache("test", String.class);

            final String result = cache.get("key", k -> null);

            assertThat(result).isNull();
        }

        @Test
        void shouldPassKeyToLoader() {
            final Cache<String> cache = provider.getCache("test", String.class);

            final String result = cache.get("testKey", k -> "loaded:" + k);

            assertThat(result).isEqualTo("loaded:testKey");
        }

    }

    @Nested
    class CachePutTest {

        @Test
        void shouldStoreValue() {
            final Cache<String> cache = provider.getCache("test", String.class);

            cache.put("key", "value");

            assertThat(cache.get("key", k -> "other")).isEqualTo("value");
        }

        @Test
        void shouldOverwriteExistingValue() {
            final Cache<String> cache = provider.getCache("test", String.class);

            cache.put("key", "first");
            cache.put("key", "second");

            assertThat(cache.get("key", k -> "other")).isEqualTo("second");
        }

    }

    @Nested
    class CacheInvalidateTest {

        @Test
        void shouldRemoveSpecifiedKeys() {
            final Cache<String> cache = provider.getCache("test", String.class);
            cache.put("key1", "value1");
            cache.put("key2", "value2");
            cache.put("key3", "value3");

            cache.invalidate(List.of("key1", "key2"));

            assertThat(cache.get("key1", k -> "new1")).isEqualTo("new1");
            assertThat(cache.get("key2", k -> "new2")).isEqualTo("new2");
            assertThat(cache.get("key3", k -> "new3")).isEqualTo("value3");
        }

        @Test
        void shouldHandleEmptyCollection() {
            final Cache<String> cache = provider.getCache("test", String.class);
            cache.put("key", "value");

            cache.invalidate(List.of());

            assertThat(cache.get("key", k -> "other")).isEqualTo("value");
        }

        @Test
        void shouldHandleNonExistentKeys() {
            final Cache<String> cache = provider.getCache("test", String.class);
            cache.put("key", "value");

            cache.invalidate(List.of("nonExistent"));

            assertThat(cache.get("key", k -> "other")).isEqualTo("value");
        }

    }

    @Nested
    class CacheInvalidateAllTest {

        @Test
        void shouldRemoveAllEntries() {
            final Cache<String> cache = provider.getCache("test", String.class);
            cache.put("key1", "value1");
            cache.put("key2", "value2");
            cache.put("key3", "value3");

            cache.invalidateAll();

            assertThat(cache.get("key1", k -> "new1")).isEqualTo("new1");
            assertThat(cache.get("key2", k -> "new2")).isEqualTo("new2");
            assertThat(cache.get("key3", k -> "new3")).isEqualTo("new3");
        }

        @Test
        void shouldHandleEmptyCache() {
            final Cache<String> cache = provider.getCache("test", String.class);

            cache.invalidateAll();

            assertThat(cache.get("key", k -> "value")).isEqualTo("value");
        }

    }

}