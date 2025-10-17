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
package org.dependencytrack.filestorage.local;

import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.DeploymentConfigDefinition;

import java.nio.file.Path;

/**
 * @since 5.7.0
 */
final class LocalFileStorageConfigs {

    static final ConfigDefinition<Path> CONFIG_DIRECTORY =
            new DeploymentConfigDefinition<>("directory", ConfigTypes.PATH, /* isRequired */ true);
    static final ConfigDefinition<Integer> CONFIG_COMPRESSION_LEVEL =
            new DeploymentConfigDefinition<>("compression.level", ConfigTypes.INTEGER, /* isRequired */ false);
    static final int CONFIG_COMPRESSION_LEVEL_DEFAULT = 5;

    private LocalFileStorageConfigs() {
    }

}
