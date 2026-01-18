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
package org.dependencytrack.vulndatasource.github;

import io.github.jeremylong.openvulnerability.client.HttpAsyncClientSupplier;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import static io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder.aGitHubSecurityAdvisoryClient;

/**
 * @since 5.7.0
 */
final class GitHubVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;
    private ExtensionKVStore kvStore;
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
    public void init(final ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
        this.kvStore = ctx.kvStore();
        this.httpClientSupplier = () -> HttpAsyncClients.custom()
                .setRetryStrategy(new GitHubHttpRequestRetryStrategy())
                .setProxySelector(ctx.proxySelector())
                .build();
    }

    @Override
    public boolean isDataSourceEnabled() {
        return configRegistry.getRuntimeConfig(GitHubVulnDataSourceConfig.class).getEnabled();
    }

    @Override
    public VulnDataSource create() {
        final var config = configRegistry.getRuntimeConfig(GitHubVulnDataSourceConfig.class);
        if (!config.getEnabled()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), this.kvStore);

        final GitHubSecurityAdvisoryClientBuilder clientBuilder = aGitHubSecurityAdvisoryClient()
                .withHttpClientSupplier(httpClientSupplier)
                .withEndpoint(config.getApiUrl().toString())
                .withApiKey(config.getApiToken());
        if (watermarkManager.getWatermark() != null) {
            clientBuilder.withUpdatedSinceFilter(
                    ZonedDateTime.ofInstant(watermarkManager.getWatermark(), ZoneOffset.UTC));
        }
        final GitHubSecurityAdvisoryClient client = clientBuilder.build();

        return new GitHubVulnDataSource(watermarkManager, client, config.getAliasSyncEnabled());
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new GitHubVulnDataSourceConfig()
                .withEnabled(false)
                .withAliasSyncEnabled(true)
                .withApiUrl(URI.create("https://api.github.com/graphql"));

        return new RuntimeConfigSpec(defaultConfig);
    }

}
