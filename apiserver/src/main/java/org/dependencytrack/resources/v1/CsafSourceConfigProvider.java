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
package org.dependencytrack.resources.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.datasource.vuln.csaf.CsafSource;
import org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs;
import org.dependencytrack.datasource.vuln.csaf.SourcesManager;
import org.dependencytrack.plugin.ConfigRegistryImpl;

import javax.annotation.Nullable;
import java.util.List;

/**
 * Helper class to manage CSAF source configurations from the runtime configuration of the plugin system.
 */
public class CsafSourceConfigProvider {

    /**
     * Returns a CSAF source by its ID from the configuration.
     *
     * @param id the ID of the CSAF source
     * @return the CSAF source, or null if not found
     */
    @Nullable
    static CsafSource getCsafSourceByIdFromConfig(List<CsafSource> sources, int id) {
        // Fetch existing aggregators and look for the specific one
        return sources.stream()
                .filter(s -> s.getId() == id)
                .findFirst().orElse(null);
    }

    /**
     * Updates the CSAF sources in the configuration.
     *
     * @param sources the list of CSAF sources to set in the configuration.
     */
    static void updateSourcesInConfig(List<CsafSource> sources) {
        var config = ConfigRegistryImpl.forExtension("vuln.datasource", "csaf");
        config.setValue(
                CsafVulnDataSourceConfigs.CONFIG_SOURCES,
                SourcesManager.serializeSources(new ObjectMapper().registerModule(new JavaTimeModule()), sources)
        );
    }

}
