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

import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;

final class TestSecretManager implements SecretManager {

    public static final String NAME = "test";

    @Override
    public @NonNull String name() {
        return NAME;
    }

    @Override
    public boolean isReadOnly() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void createSecret(
            final @NonNull String name,
            final String description,
            final @NonNull String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean updateSecret(
            final @NonNull String name,
            final String description,
            final String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteSecret(final @NonNull String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public @Nullable String getSecretValue(final @NonNull String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public @NonNull List<SecretMetadata> listSecrets() {
        throw new UnsupportedOperationException();
    }

}