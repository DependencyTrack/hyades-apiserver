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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.SequencedCollection;

import static org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs.CONFIG_SOURCES;

/**
 * @since 5.7.0
 */
public class CsafVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsafVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;
    private ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "csaf";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return CsafVulnDataSource.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> runtimeConfigs() {
        return List.of(
                CONFIG_ENABLED,
                CONFIG_SOURCES);
    }

    @Override
    public void init(final ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Override
    public boolean isDataSourceEnabled() {
        return this.configRegistry.getOptionalValue(CONFIG_ENABLED).orElse(false);
    }

    @Override
    public VulnDataSource create() {
        if (!isDataSourceEnabled()) {
            LOGGER.info("Disabled; Not creating an instance");
            return null;
        }

        final var sourcesManagers = SourcesManager.create(configRegistry, objectMapper);
        return new CsafVulnDataSource(sourcesManagers);
    }

}
