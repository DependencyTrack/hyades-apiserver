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
package org.dependencytrack.vulndatasource.nvd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;

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
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new NvdVulnDataSourceConfig()
                .withEnabled(true)
                .withCveFeedsUrl(URI.create("https://nvd.nist.gov/feeds"));

        return new RuntimeConfigSpec(defaultConfig);
    }

    @Override
    public boolean isDataSourceEnabled() {
        return configRegistry.getRuntimeConfig(NvdVulnDataSourceConfig.class).getEnabled();
    }

    @Override
    public VulnDataSource create() {
        final var config = configRegistry.getRuntimeConfig(NvdVulnDataSourceConfig.class);
        if (!config.getEnabled()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }

        final var watermarkManager = WatermarkManager.create(kvStore);

        return new NvdVulnDataSource(watermarkManager, objectMapper, httpClient, config.getCveFeedsUrl().toString());
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

}
