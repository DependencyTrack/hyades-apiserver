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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public final class CachingSecretManager implements SecretManager {

    private final SecretManager delegate;
    private final Cache<String, Optional<String>> cache;

    CachingSecretManager(
            SecretManager delegate,
            long expireAfterWriteMillis,
            int maxSize) {
        this.delegate = requireNonNull(delegate, "delegate must not be null");
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(expireAfterWriteMillis, TimeUnit.MILLISECONDS)
                .maximumSize(maxSize)
                .build();
    }

    public static SecretManager maybeWrap(
            SecretManager delegate,
            Config config) {
        final var cacheConfig = new CachingSecretManagerConfig(config);
        if (!cacheConfig.isEnabled()) {
            return delegate;
        }

        return new CachingSecretManager(
                delegate,
                cacheConfig.getExpireAfterWriteMillis(),
                cacheConfig.getMaxSize());
    }

    public SecretManager getDelegate() {
        return delegate;
    }

    @Override
    public String name() {
        return delegate.name();
    }

    @Override
    public boolean isReadOnly() {
        return delegate.isReadOnly();
    }

    @Override
    public void createSecret(
            String name,
            @Nullable String description,
            String value) {
        delegate.createSecret(name, description, value);
        cache.invalidate(name);
    }

    @Override
    public boolean updateSecret(
            String name,
            @Nullable String description,
            @Nullable String value) {
        final boolean updated = delegate.updateSecret(name, description, value);
        if (updated) {
            cache.invalidate(name);
        }
        return updated;
    }

    @Override
    public void deleteSecret(String name) {
        delegate.deleteSecret(name);
        cache.invalidate(name);
    }

    @Override
    public @Nullable SecretMetadata getSecretMetadata(String name) {
        return delegate.getSecretMetadata(name);
    }

    @Override
    public @Nullable String getSecretValue(String name) {
        return cache.get(name, secretName -> Optional.ofNullable(delegate.getSecretValue(secretName))).orElse(null);
    }

    @Override
    public Page<SecretMetadata> listSecretMetadata(ListSecretsRequest request) {
        return delegate.listSecretMetadata(request);
    }

    @Override
    public void close() {
        delegate.close();
    }

}
