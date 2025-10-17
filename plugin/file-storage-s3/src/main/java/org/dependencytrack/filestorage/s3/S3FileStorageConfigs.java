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
package org.dependencytrack.filestorage.s3;

import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.DeploymentConfigDefinition;

/**
 * @since 5.7.0
 */
final class S3FileStorageConfigs {

    static final ConfigDefinition<String> CONFIG_ENDPOINT =
            new DeploymentConfigDefinition<>("endpoint", ConfigTypes.STRING, /* isRequired */ true);
    static final ConfigDefinition<String> CONFIG_BUCKET =
            new DeploymentConfigDefinition<>("bucket", ConfigTypes.STRING, /* isRequired */ true);
    static final ConfigDefinition<String> CONFIG_ACCESS_KEY =
            new DeploymentConfigDefinition<>("access.key", ConfigTypes.STRING, /* isRequired */ false);
    static final ConfigDefinition<String> CONFIG_SECRET_KEY =
            new DeploymentConfigDefinition<>("secret.key", ConfigTypes.STRING, /* isRequired */ false);
    static final ConfigDefinition<String> CONFIG_REGION =
            new DeploymentConfigDefinition<>("region", ConfigTypes.STRING, /* isRequired */ false);
    static final ConfigDefinition<Integer> CONFIG_COMPRESSION_LEVEL =
            new DeploymentConfigDefinition<>("compression.level", ConfigTypes.INTEGER, /* isRequired */ false);
    static final int CONFIG_COMPRESSION_LEVEL_DEFAULT = 5;

    private S3FileStorageConfigs() {
    }

}
