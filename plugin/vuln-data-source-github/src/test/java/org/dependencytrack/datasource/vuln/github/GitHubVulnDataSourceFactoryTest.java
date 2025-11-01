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

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.MockConfigRegistry;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_API_TOKEN;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_API_URL;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_ENABLED;

class GitHubVulnDataSourceFactoryTest {

    @Test
    void extensionNameShouldBeGitHub() {
        try (final var datasourceFactory = new GitHubVulnDataSourceFactory()) {
            assertThat(datasourceFactory.extensionName()).isEqualTo("github");
        }
    }

    @Test
    void extensionClassShouldBeGitHubVulnDataSource() {
        try (final var datasourceFactory = new GitHubVulnDataSourceFactory()) {
            assertThat(datasourceFactory.extensionClass()).isEqualTo(GitHubVulnDataSource.class);
        }
    }

    @Test
    void priorityShouldBeZero() {
        try (final var datasourceFactory = new GitHubVulnDataSourceFactory()) {
            assertThat(datasourceFactory.priority()).isZero();
        }
    }

    @Test
    void runtimeConfigsShouldHaveNameAndDescription() {
        try (final var datasourceFactory = new GitHubVulnDataSourceFactory()) {
            assertThat(datasourceFactory.runtimeConfigs()).allSatisfy(config -> {
                assertThat(config.name()).isNotBlank();
                assertThat(config.description()).isNotBlank();
            });
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isDataSourceEnabledShouldReturnTrueWhenEnabledAndFalseOtherwise(final boolean isEnabled) {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_ENABLED, isEnabled);

        try (final var dataSourceFactory = new GitHubVulnDataSourceFactory()) {
            dataSourceFactory.init(new ExtensionContext(configRegistry));
            assertThat(dataSourceFactory.isDataSourceEnabled()).isEqualTo(isEnabled);
        }
    }

    @Test
    void createShouldReturnNullWhenDisabled() throws Exception {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_ENABLED, false);
        configRegistry.setValue(CONFIG_API_URL, URI.create("http://localhost:6666").toURL());
        configRegistry.setValue(CONFIG_API_TOKEN, "apiToken");

        try (final var dataSourceFactory = new GitHubVulnDataSourceFactory()) {
            dataSourceFactory.init(new ExtensionContext(configRegistry));
            assertThat(dataSourceFactory.create()).isNull();
        }
    }

    @Test
    void createShouldReturnDataSource() throws Exception {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_ENABLED, true);
        configRegistry.setValue(CONFIG_API_URL, URI.create("http://localhost:6666").toURL());
        configRegistry.setValue(CONFIG_API_TOKEN, "apiToken");

        try (final var dataSourceFactory = new GitHubVulnDataSourceFactory()) {
            dataSourceFactory.init(new ExtensionContext(configRegistry));

            final VulnDataSource dataSource = dataSourceFactory.create();
            assertThat(dataSource).isNotNull();
            dataSource.close();
        }
    }

    @Test
    void createShouldThrowWhenApiUrlIsNull() {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_ENABLED, true);
        configRegistry.setValue(CONFIG_API_TOKEN, "apiToken");

        try (final var dataSourceFactory = new GitHubVulnDataSourceFactory()) {
            dataSourceFactory.init(new ExtensionContext(configRegistry));

            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(dataSourceFactory::create);
        }
    }

    @Test
    void createShouldThrowWhenApiTokenIsNull() throws Exception {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_ENABLED, true);
        configRegistry.setValue(CONFIG_API_URL, URI.create("http://localhost:6666").toURL());
        configRegistry.setValue(CONFIG_API_TOKEN, null);

        try (final var dataSourceFactory = new GitHubVulnDataSourceFactory()) {
            dataSourceFactory.init(new ExtensionContext(configRegistry));

            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(dataSourceFactory::create);
        }
    }

}