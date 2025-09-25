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
package org.dependencytrack.datasource.vuln.github;

import io.github.jeremylong.openvulnerability.client.HttpAsyncClientSupplier;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.SequencedCollection;

import static io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder.aGitHubSecurityAdvisoryClient;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_API_TOKEN;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_API_URL;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_WATERMARK;

/**
 * @since 5.7.0
 */
final class GitHubVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;
    private HttpAsyncClientSupplier httpClientSupplier;

    @Override
    public String extensionName() {
        return "github";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return GitHubVulnDataSource.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> runtimeConfigs() {
        return List.of(
                CONFIG_ENABLED,
                CONFIG_ALIAS_SYNC_ENABLED,
                CONFIG_API_URL,
                CONFIG_API_TOKEN,
                CONFIG_WATERMARK);
    }

    @Override
    public void init(final ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
        this.httpClientSupplier = () -> HttpAsyncClients.custom()
                .setRetryStrategy(new GitHubHttpRequestRetryStrategy())
                .setProxySelector(ctx.proxySelector())
                .build();
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

        final URL apiUrl = this.configRegistry.getValue(CONFIG_API_URL);
        final String apiToken = this.configRegistry.getValue(CONFIG_API_TOKEN);
        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), this.configRegistry);
        final boolean isAliasSyncEnabled = this.configRegistry.getOptionalValue(CONFIG_ALIAS_SYNC_ENABLED).orElse(false);

        final GitHubSecurityAdvisoryClientBuilder clientBuilder = aGitHubSecurityAdvisoryClient()
                .withHttpClientSupplier(httpClientSupplier)
                .withEndpoint(apiUrl.toString())
                .withApiKey(apiToken);
        if (watermarkManager.getWatermark() != null) {
            clientBuilder.withUpdatedSinceFilter(
                    ZonedDateTime.ofInstant(watermarkManager.getWatermark(), ZoneOffset.UTC));
        }
        final GitHubSecurityAdvisoryClient client = clientBuilder.build();

        return new GitHubVulnDataSource(watermarkManager, client, isAliasSyncEnabled);
    }

}
