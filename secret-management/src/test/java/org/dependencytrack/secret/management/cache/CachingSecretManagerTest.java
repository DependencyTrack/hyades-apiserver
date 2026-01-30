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
package org.dependencytrack.secret.management.cache;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atMostOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class CachingSecretManagerTest {

    private final SecretManager delegateMock = mock(SecretManager.class);
    private final CachingSecretManager secretManager = new CachingSecretManager(delegateMock, 1000, 5);

    @Test
    void nameShouldReturnDelegateName() {
        doReturn("delegate").when(delegateMock).name();
        assertThat(secretManager.name()).isEqualTo("delegate");
    }

    @Test
    void getDelegateShouldReturnDelegate() {
        assertThat(secretManager.getDelegate()).isEqualTo(delegateMock);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isReadOnlyShouldReturnDelegateIsReadOnly(final boolean readOnly) {
        doReturn(readOnly).when(delegateMock).isReadOnly();
        assertThat(secretManager.isReadOnly()).isEqualTo(readOnly);
    }

    @Test
    void getSecretValueShouldCacheResult() {
        doReturn("value").when(delegateMock).getSecretValue("foo");

        assertThat(secretManager.getSecretValue("foo")).isEqualTo("value");
        assertThat(secretManager.getSecretValue("foo")).isEqualTo("value");

        verify(delegateMock, atMostOnce()).getSecretValue(eq("foo"));
    }

    @Test
    void shouldInvalidateCacheWhenSecretIsCreated() {
        doReturn("value", "updatedValue").when(delegateMock).getSecretValue("foo");
        assertThat(secretManager.getSecretValue("foo")).isEqualTo("value");

        secretManager.createSecret("foo", null, "updatedValue");
        verify(delegateMock).createSecret(eq("foo"), isNull(), eq("updatedValue"));

        assertThat(secretManager.getSecretValue("foo")).isEqualTo("updatedValue");
    }

    @Test
    void shouldInvalidateCacheWhenSecretIsUpdated() {
        doReturn("value", "updatedValue").when(delegateMock).getSecretValue("foo");
        assertThat(secretManager.getSecretValue("foo")).isEqualTo("value");

        doReturn(true).when(delegateMock).updateSecret(eq("foo"), any(), eq("updatedValue"));
        secretManager.updateSecret("foo", null, "updatedValue");

        assertThat(secretManager.getSecretValue("foo")).isEqualTo("updatedValue");
    }

    @Test
    void shouldInvalidateCacheWhenSecretIsDeleted() {
        doReturn("value", null).when(delegateMock).getSecretValue("foo");
        assertThat(secretManager.getSecretValue("foo")).isEqualTo("value");

        secretManager.deleteSecret("foo");
        verify(delegateMock).deleteSecret(eq("foo"));

        assertThat(secretManager.getSecretValue("foo")).isNull();
    }

    @Test
    void getSecretMetadataShouldBypassCache() {
        final var secretMetadata = new SecretMetadata("foo", "description", null, null);

        doReturn(secretMetadata).when(delegateMock).getSecretMetadata("foo");

        assertThat(secretManager.getSecretMetadata("foo")).isEqualTo(secretMetadata);
        assertThat(secretManager.getSecretMetadata("foo")).isEqualTo(secretMetadata);

        verify(delegateMock, times(2)).getSecretMetadata("foo");
    }

    @Test
    void listSecretMetadataShouldBypassCache() {
        final var secretMetadata = new SecretMetadata("foo", null, null, null);
        final var request = new ListSecretsRequest(null, null, 100);

        doReturn(new Page<>(List.of(secretMetadata))).when(delegateMock).listSecretMetadata(any());

        assertThat(secretManager.listSecretMetadata(request).items()).containsExactly(secretMetadata);
        assertThat(secretManager.listSecretMetadata(request).items()).containsExactly(secretMetadata);

        verify(delegateMock, times(2)).listSecretMetadata(any());
    }

    @Test
    void closeShouldCloseDelegate() {
        secretManager.close();
        verify(delegateMock).close();
    }

}