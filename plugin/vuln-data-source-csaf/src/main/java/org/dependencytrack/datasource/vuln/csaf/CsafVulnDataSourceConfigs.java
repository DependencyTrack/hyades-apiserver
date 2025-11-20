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
package org.dependencytrack.datasource.vuln.csaf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * @since 5.7.0
 */
public class CsafVulnDataSourceConfigs {

    public static final RuntimeConfigDefinition<Boolean> CONFIG_ENABLED;
    public static final RuntimeConfigDefinition<String> CONFIG_SOURCES;

    static {
        final URL defaultApiUrl;
        try {
            defaultApiUrl = URI.create("https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json").toURL();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Failed to parse default API URL", e);
        }

        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());;
        final String defaultSources;
        try {
            defaultSources = objectMapper.writeValueAsString(new ArrayList<>(List.of(
                    new CsafSource(
                            "CERT-Bund CSAF Aggregator",
                            defaultApiUrl.toString(),
                            true,
                            false,
                            false,
                            false
                    )
            )));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize default sources", e);
        }

        CONFIG_ENABLED = new RuntimeConfigDefinition<>(
                "enabled",
                "Whether the CSAF data source should be enabled",
                ConfigTypes.BOOLEAN,
                /* defaultValue */ false,
                /* isRequired */ false,
                /* isSecret */ false);
        CONFIG_SOURCES =  new RuntimeConfigDefinition<>(
                "sources",
                "Where the CSAF documents are located",
                ConfigTypes.STRING,
                defaultSources,
                /* isRequired */ false,
                /* isSecret */ false);
    }

    private CsafVulnDataSourceConfigs() {
    }

}
