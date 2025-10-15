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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.net.http.HttpClient;
import java.util.Collections;
import java.util.List;
import java.util.SequencedCollection;

import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_DATA_URL;
import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_ECOSYSTEMS;
import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_WATERMARKS;

/**
 * @since 5.7.0
 */
final class OsvVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;
    private ObjectMapper objectMapper;
    private HttpClient httpClient;

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
        return PRIORITY_HIGHEST + 100;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> runtimeConfigs() {
        return List.of(
                CONFIG_ENABLED,
                CONFIG_DATA_URL,
                CONFIG_ECOSYSTEMS,
                CONFIG_WATERMARKS,
                CONFIG_ALIAS_SYNC_ENABLED);
    }

    @Override
    public void init(ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
        this.httpClient = HttpClient.newBuilder()
                .proxy(ctx.proxySelector())
                .build();
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }

    @Override
    public boolean isDataSourceEnabled() {
        return this.configRegistry.getOptionalValue(CONFIG_ENABLED).orElse(false);
    }

    @Override
    public VulnDataSource create() {
        if (!configRegistry.getOptionalValue(CONFIG_ENABLED).orElse(false)) {
            LOGGER.info("Disabled; Not creating an instance");
            return null;
        }

        final URL dataUrl = configRegistry.getValue(CONFIG_DATA_URL);
        final List<String> ecosystems = configRegistry
                .getOptionalValue(CONFIG_ECOSYSTEMS)
                .orElseGet(Collections::emptyList);
        final var watermarkManager = WatermarkManager.create(configRegistry, objectMapper);
        final boolean isAliasSyncEnabled = this.configRegistry.getOptionalValue(CONFIG_ALIAS_SYNC_ENABLED).orElse(false);

        return new OsvVulnDataSource(watermarkManager, objectMapper, dataUrl, ecosystems, httpClient, isAliasSyncEnabled);
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
        VulnDataSourceFactory.super.close();
    }

}