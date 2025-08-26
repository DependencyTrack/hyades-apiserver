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

import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;

import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_ECOSYSTEMS;
import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_ENABLED;

/**
 * @since 5.7.0
 */
final class OsvVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;

    @Override
    public String extensionName() {
        return "osv";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return OsvVulnDataSource.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public void init(final ConfigRegistry configRegistry) {
        this.configRegistry = configRegistry;
        configRegistry.setValue(CONFIG_ENABLED, true);
        configRegistry.setValue(CONFIG_ECOSYSTEMS, List.of("Maven", "npm"));
    }

    @Override
    public VulnDataSource create() {
        if (!configRegistry.getOptionalValue(CONFIG_ENABLED).orElse(false)) {
            LOGGER.info("Disabled; Not creating an instance");
            return null;
        }

        final List<String> ecosystems = configRegistry
                .getOptionalValue(CONFIG_ECOSYSTEMS)
                .orElseGet(Collections::emptyList);

        return new OsvVulnDataSource(ecosystems);
    }

}
