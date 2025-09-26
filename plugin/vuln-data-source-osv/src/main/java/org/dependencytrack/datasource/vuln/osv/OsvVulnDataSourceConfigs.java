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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.List;

/**
 * @since 5.7.0
 */
final class OsvVulnDataSourceConfigs {

    static final RuntimeConfigDefinition<Boolean> CONFIG_ENABLED;
    static final RuntimeConfigDefinition<URL> CONFIG_DATA_URL;
    static final RuntimeConfigDefinition<List<String>> CONFIG_ECOSYSTEMS;
    static final RuntimeConfigDefinition<Instant> CONFIG_WATERMARK;

    static {
        final URL dataUrl;
        try {
            dataUrl = URI.create("https://storage.googleapis.com/osv-vulnerabilities").toURL();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid data URL", e);
        }

        CONFIG_ENABLED = new RuntimeConfigDefinition<>(
                "enabled",
                "Whether the OSV data source should be enabled",
                ConfigTypes.BOOLEAN,
                false,
                false,
                false);
        CONFIG_DATA_URL = new RuntimeConfigDefinition<>(
                "data.url",
                "Base URL for OSV",
                ConfigTypes.URL, dataUrl,
                true,
                false);
        CONFIG_ECOSYSTEMS = new RuntimeConfigDefinition<>(
                "ecosystems",
                "List of OSV ecosystems to mirror",
                ConfigTypes.STRING_LIST,
                List.of("Go", "Maven", "npm", "NuGet", "PyPI"),
                false,
                false);
        CONFIG_WATERMARK = new RuntimeConfigDefinition<>(
                "watermark",
                "Highest observed modification timestamp of processed vulnerabilities",
                ConfigTypes.INSTANT,
                /* defaultValue */ null,
                /* isRequired */ false,
                /* isSecret */ false);
    }

    private OsvVulnDataSourceConfigs() {
    }

}