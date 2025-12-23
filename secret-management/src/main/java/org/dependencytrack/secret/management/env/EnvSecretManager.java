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
import org.dependencytrack.secret.management.SecretMetadata;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

/**
 * @since 5.7.0
 */
final class EnvSecretManager implements SecretManager {

    private final Map<String, String> secretValueByName;

    EnvSecretManager(Map<String, String> secretValueByName) {
        this.secretValueByName = secretValueByName;
    }

    @Override
    public String name() {
        return "env";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public void createSecret(String name, @Nullable String description, String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean updateSecret(String name, @Nullable String description, @Nullable String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteSecret(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public @Nullable String getSecretValue(String name) {
        return secretValueByName.get(name);
    }

    @Override
    public List<SecretMetadata> listSecrets() {
        return secretValueByName.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> new SecretMetadata(
                        entry.getKey(),
                        null,
                        null,
                        null))
                .toList();
    }

}
