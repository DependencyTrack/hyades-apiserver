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
package org.dependencytrack.datasource.vuln.nvd;

import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Instant;

/**
 * @since 5.7.0
 */
final class NvdVulnDataSourceConfigs {

    static final RuntimeConfigDefinition<Boolean> CONFIG_ENABLED;
    static final RuntimeConfigDefinition<URL> CONFIG_FEEDS_URL;
    static final RuntimeConfigDefinition<Instant> CONFIG_WATERMARK;

    static {
        final URL defaultFeedsUrl;
        try {
            defaultFeedsUrl = URI.create("https://nvd.nist.gov/feeds").toURL();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid default feeds URL", e);
        }

        CONFIG_ENABLED = new RuntimeConfigDefinition<>(
                "enabled", "", ConfigTypes.BOOLEAN, true, false, false);
        CONFIG_FEEDS_URL = new RuntimeConfigDefinition<>(
                "feeds.url", "Base URL of NVD feeds", ConfigTypes.URL, defaultFeedsUrl, true, false);
        CONFIG_WATERMARK = new RuntimeConfigDefinition<>(
                "watermark", "", ConfigTypes.INSTANT, null, false, false);
    }

    private NvdVulnDataSourceConfigs() {
    }

}
