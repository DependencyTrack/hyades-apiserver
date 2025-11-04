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
package org.dependencytrack.secret;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.cache.CachingSecretManager;
import org.eclipse.microprofile.config.Config;
import org.junit.After;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SecretManagerInitializerTest {

    @After
    public void afterEach() {
        if (SecretManagerInitializer.INSTANCE != null) {
            SecretManagerInitializer.INSTANCE.close();
            SecretManagerInitializer.INSTANCE = null;
        }
    }

    @Test
    public void shouldInitializeSecretManagerWithoutCaching() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.secret-management.provider", "test")
                .withDefaultValue("dt.secret-management.cache.enabled", "false")
                .build();

        new SecretManagerInitializer(config).contextInitialized(null);

        assertThat(SecretManagerInitializer.INSTANCE)
                .isInstanceOf(TestSecretManager.class)
                .isNotInstanceOf(CachingSecretManager.class);
        assertThat(SecretManagerInitializer.INSTANCE.name()).isEqualTo("test");
    }

    @Test
    public void shouldInitializeSecretManagerWithCaching() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.secret-management.provider", "test")
                .withDefaultValue("dt.secret-management.cache.enabled", "true")
                .withDefaultValue("dt.secret-management.cache.expire-after-write-ms", "60000")
                .withDefaultValue("dt.secret-management.cache.max-size", "100")
                .build();

        new SecretManagerInitializer(config).contextInitialized(null);

        assertThat(SecretManagerInitializer.INSTANCE).isInstanceOf(CachingSecretManager.class);

        final var cachingManager = (CachingSecretManager) SecretManagerInitializer.INSTANCE;
        assertThat(cachingManager.name()).isEqualTo("test");
        assertThat(cachingManager.getDelegate()).isInstanceOf(TestSecretManager.class);
    }

    @Test
    public void shouldThrowForUnknownType() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.secret-management.provider", "unknown")
                .build();

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> new SecretManagerInitializer(config).contextInitialized(null))
                .withMessage("No secret management provider found for name: unknown");

        assertThat(SecretManagerInitializer.INSTANCE).isNull();
    }

    @Test
    public void shouldCloseAndNullifyInstance() {
        final var secretManagerMock = mock(SecretManager.class);
        SecretManagerInitializer.INSTANCE = secretManagerMock;

        new SecretManagerInitializer(mock(Config.class)).contextDestroyed(null);

        verify(secretManagerMock).close();
        assertThat(SecretManagerInitializer.INSTANCE).isNull();
    }

}