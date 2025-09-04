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

import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.dependencytrack.datasource.vuln.nvd.NvdVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.nvd.NvdVulnDataSourceConfigs.CONFIG_FEEDS_URL;

/**
 * @since 5.7.0
 */
final class NvdVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(NvdVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;

    @Override
    public String extensionName() {
        return "nvd";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return NvdVulnDataSource.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public void init(final ConfigRegistry configRegistry) {
        this.configRegistry = configRegistry;
        configRegistry.setValue(CONFIG_ENABLED, false);
        configRegistry.setValue(CONFIG_FEEDS_URL, "https://nvd.nist.gov/feeds");
    }

    @Override
    public VulnDataSource create() {
        if (!configRegistry.getOptionalValue(CONFIG_ENABLED).orElse(false)) {
            LOGGER.info("Disabled; Not creating an instance");
            return null;
        }

        final String feedsUrl = configRegistry.getValue(CONFIG_FEEDS_URL);
        return new NvdVulnDataSource(feedsUrl);
    }

}
