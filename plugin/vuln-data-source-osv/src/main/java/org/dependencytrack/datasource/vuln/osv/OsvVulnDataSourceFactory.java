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
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Set;

/**
 * @since 5.7.0
 */
final class OsvVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;
    private ExtensionKVStore kvStore;
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
    public void init(ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
        this.kvStore = ctx.kvStore();
        this.httpClient = HttpClient.newBuilder()
                .proxy(ctx.proxySelector())
                .build();
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new OSVVulnDataSourceConfig()
                .withEnabled(false)
                .withAliasSyncEnabled(false)
                .withDataUrl(URI.create("https://storage.googleapis.com/osv-vulnerabilities"))
                .withEcosystems(Set.of("Go", "Maven", "npm", "NuGet", "PyPI"));

        return new RuntimeConfigSpec(defaultConfig);
    }

    @Override
    public boolean isDataSourceEnabled() {
        return configRegistry.getRuntimeConfig(OSVVulnDataSourceConfig.class).getEnabled();
    }

    @Override
    public VulnDataSource create() {
        final var config = configRegistry.getRuntimeConfig(OSVVulnDataSourceConfig.class);
        if (!config.getEnabled()) {
            LOGGER.info("Disabled; Not creating an instance");
            return null;
        }

        final var watermarkManager = WatermarkManager.create(config.getEcosystems(), kvStore);

        return new OsvVulnDataSource(
                watermarkManager,
                objectMapper,
                config.getDataUrl().toString(),
                config.getEcosystems(),
                httpClient,
                config.getAliasSyncEnabled());
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

}