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
package org.dependencytrack.datasource.vuln;

import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.time.Instant;

/**
 * @since 5.7.0
 */
final class GitHubVulnDataSourceConfigs {

    static final RuntimeConfigDefinition<Boolean> CONFIG_ENABLED =
            new RuntimeConfigDefinition<>("enabled", "", ConfigTypes.BOOLEAN, false, false, false);
    static final RuntimeConfigDefinition<String> CONFIG_API_ENDPOINT =
            new RuntimeConfigDefinition<>("api.endpoint", "", ConfigTypes.STRING, "https://api.github.com/graphql", false, false);
    static final RuntimeConfigDefinition<String> CONFIG_API_TOKEN =
            new RuntimeConfigDefinition<>("api.token", "", ConfigTypes.STRING, null, true, true);
    static final RuntimeConfigDefinition<Instant> CONFIG_LAST_UPDATED_TIMESTAMP =
            new RuntimeConfigDefinition<>("last.updated", "", ConfigTypes.INSTANT, null, false, false);

    private GitHubVulnDataSourceConfigs() {
    }

}
