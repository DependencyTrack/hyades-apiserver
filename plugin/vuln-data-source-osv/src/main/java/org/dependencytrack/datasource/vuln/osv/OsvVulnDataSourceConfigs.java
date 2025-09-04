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
package org.dependencytrack.datasource.vuln.osv;

import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.util.List;

/**
 * @since 5.7.0
 */
final class OsvVulnDataSourceConfigs {

    static final RuntimeConfigDefinition<Boolean> CONFIG_ENABLED =
            new RuntimeConfigDefinition<>("enabled", "", ConfigTypes.BOOLEAN, false, false);
    static final RuntimeConfigDefinition<List<String>> CONFIG_ECOSYSTEMS =
            new RuntimeConfigDefinition<>("ecosystems", "", ConfigTypes.STRING_LIST, false, false);

    private OsvVulnDataSourceConfigs() {
    }

}
