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
package org.dependencytrack.datasource.vuln;

import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.SequencedCollection;

import static io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder.aGitHubSecurityAdvisoryClient;
import static org.dependencytrack.datasource.vuln.GitHubVulnDataSourceConfigs.CONFIG_API_ENDPOINT;
import static org.dependencytrack.datasource.vuln.GitHubVulnDataSourceConfigs.CONFIG_API_TOKEN;
import static org.dependencytrack.datasource.vuln.GitHubVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.GitHubVulnDataSourceConfigs.CONFIG_LAST_UPDATED_TIMESTAMP;

/**
 * @since 5.7.0
 */
final class GitHubVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;

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
        return PRIORITY_HIGHEST + 120;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> runtimeConfigs() {
        return List.of(
                CONFIG_ENABLED,
                CONFIG_API_ENDPOINT,
                CONFIG_API_TOKEN,
                CONFIG_LAST_UPDATED_TIMESTAMP);
    }

    @Override
    public void init(final ConfigRegistry configRegistry) {
        this.configRegistry = configRegistry;
    }

    @Override
    public VulnDataSource create() {
        if (!configRegistry.getOptionalValue(CONFIG_ENABLED).orElse(false)) {
            LOGGER.warn("Disabled; Not creating an instance");
            return null;
        }

        final GitHubSecurityAdvisoryClient client = createClient();
        return new GitHubVulnDataSource(client, this::setLastUpdatedTimestamp);
    }

    private GitHubSecurityAdvisoryClient createClient() {
        final HttpAsyncClientBuilder httpClientBuilder = HttpAsyncClients.custom()
                .setRetryStrategy(new GitHubHttpRequestRetryStrategy())
                .useSystemProperties();

        final GitHubSecurityAdvisoryClientBuilder builder = aGitHubSecurityAdvisoryClient()
                .withApiKey(configRegistry.getValue(CONFIG_API_TOKEN))
                .withHttpClientSupplier(httpClientBuilder::build);

        configRegistry
                .getOptionalValue(CONFIG_API_ENDPOINT)
                .ifPresent(builder::withEndpoint);

        configRegistry
                .getOptionalValue(CONFIG_LAST_UPDATED_TIMESTAMP)
                .map(timestamp -> ZonedDateTime.ofInstant(timestamp, ZoneOffset.UTC))
                .ifPresent(builder::withUpdatedSinceFilter);

        return builder.build();
    }

    private void setLastUpdatedTimestamp(final Instant lastUpdatedTimestamp) {
        configRegistry.setValue(CONFIG_LAST_UPDATED_TIMESTAMP, lastUpdatedTimestamp);
    }

}
