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
package org.dependencytrack.secret.management.env;

import org.dependencytrack.secret.management.SecretManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class EnvSecretManagerTest {

    private SecretManager secretManager;

    @BeforeEach
    void beforeEach() {
        secretManager = new EnvSecretManagerFactory(
                Map.of("dt_secret_name", "value")).create();
    }

    @AfterEach
    void afterEach() {
        if (secretManager != null) {
            secretManager.close();
        }
    }

    @Test
    void nameShouldBeEnv() {
        assertThat(secretManager.name()).isEqualTo("env");
    }

    @Test
    void isReadOnlyShouldReturnTrue() {
        assertThat(secretManager.isReadOnly()).isTrue();
    }

    @Test
    void createSecretShouldThrow() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> secretManager.createSecret("foo", null, "bar"));
    }

    @Test
    void updateSecretShouldThrow() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> secretManager.updateSecret("name", null, "foo"));
    }

    @Test
    void deleteSecretShouldThrow() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> secretManager.deleteSecret("name"));
    }

    @Test
    void getSecretValueShouldReturnValue() {
        assertThat(secretManager.getSecretValue("name")).isEqualTo("value");
    }

    @Test
    void getSecretValueShouldReturnNullWhenNotFound() {
        assertThat(secretManager.getSecretValue("doesNotExist")).isNull();
    }

    @Test
    void listSecretsShouldReturnSecretMetadata() {
        assertThat(secretManager.listSecrets()).satisfiesExactly(secretMetadata -> {
            assertThat(secretMetadata.name()).isEqualTo("name");
            assertThat(secretMetadata.description()).isNull();
            assertThat(secretMetadata.createdAt()).isNull();
            assertThat(secretMetadata.updatedAt()).isNull();
        });
    }

}