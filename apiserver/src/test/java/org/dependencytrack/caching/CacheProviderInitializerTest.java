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

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.cache.api.CacheProvider;
import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CacheProviderInitializerTest {

    @Test
    void shouldInitializeCacheProvider() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.cache.provider", "local")
                .build();

        final var initializer = new CacheProviderInitializer(config);

        final var servletContextMock = mock(ServletContext.class);

        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        verify(servletContextMock).setAttribute(eq(CacheProvider.class.getName()), any(CacheProvider.class));
    }

    @Test
    void shouldThrowWhenNoCacheProviderConfigured() {
        final var config = new SmallRyeConfigBuilder().build();

        final var initializer = new CacheProviderInitializer(config);

        assertThatExceptionOfType(NoSuchElementException.class)
                .isThrownBy(() -> initializer.contextInitialized(null))
                .withMessageContaining("config property dt.cache.provider is required");
    }

    @Test
    void shouldThrowWhenConfiguredCacheProviderDoesNotExist() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.cache.provider", "does-not-exist")
                .build();

        final var initializer = new CacheProviderInitializer(config);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> initializer.contextInitialized(null))
                .withMessage("No cache provider found for name: does-not-exist");
    }

}