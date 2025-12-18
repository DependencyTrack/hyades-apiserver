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
package org.dependencytrack.secret.management.database;

import org.eclipse.microprofile.config.Config;

import java.nio.file.Path;

/**
 * @since 5.7.0
 */
final class DatabaseSecretManagerConfig {

    private static final String PREFIX = "dt.secret-management.database.";

    private final Config config;

    DatabaseSecretManagerConfig(final Config config) {
        this.config = config;
    }

    String getDataSourceName() {
        return config.getValue(PREFIX + "datasource.name", String.class);
    }

    Path getKekKeysetPath() {
        return config.getValue(PREFIX + "kek-keyset.path", Path.class);
    }

    boolean isCreateKekKeysetIfMissing() {
        return config.getValue(PREFIX + "kek-keyset.create-if-missing", boolean.class);
    }

}
