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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.net.http.HttpClient;
import java.util.List;
import java.util.SequencedCollection;

import static org.dependencytrack.datasource.vuln.nvd.NvdVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.nvd.NvdVulnDataSourceConfigs.CONFIG_FEEDS_URL;

/**
 * @since 5.7.0
 */
final class NvdVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(NvdVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;
    private ExtensionKVStore kvStore;
    private ObjectMapper objectMapper;
    private HttpClient httpClient;

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
        return PRIORITY_HIGHEST + 110;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> runtimeConfigs() {
        return List.of(
                CONFIG_ENABLED,
                CONFIG_FEEDS_URL);
    }

    @Override
    public void init(final ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
        this.kvStore = ctx.kvStore();
        this.httpClient = HttpClient.newBuilder()
                .proxy(ctx.proxySelector())
                .build();
        this.objectMapper = new ObjectMapper()
                .configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true)
                .configure(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature(), true)
                .registerModule(new JavaTimeModule());
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

        final URL feedsUrl = configRegistry.getValue(CONFIG_FEEDS_URL);
        final var watermarkManager = WatermarkManager.create(kvStore);

        return new NvdVulnDataSource(watermarkManager, objectMapper, httpClient, feedsUrl);
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

}
