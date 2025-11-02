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
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class GitHubVulnDataSourceFactoryTest extends AbstractExtensionFactoryTest<@NonNull VulnDataSource, @NonNull GitHubVulnDataSourceFactory> {

    protected GitHubVulnDataSourceFactoryTest() {
        super(GitHubVulnDataSourceFactory.class);
    }

    @Test
    void extensionNameShouldBeGitHub() {
        assertThat(factory.extensionName()).isEqualTo("github");
    }

    @Test
    void extensionClassShouldBeGitHubVulnDataSource() {
        assertThat(factory.extensionClass()).isEqualTo(GitHubVulnDataSource.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isDataSourceEnabledShouldReturnTrueWhenEnabledAndFalseOtherwise(final boolean isEnabled) {
        final var config = (GitHubVulnDataSourceConfig) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(isEnabled);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));
        assertThat(factory.isDataSourceEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldReturnNullWhenDisabled() {
        final var config = (GitHubVulnDataSourceConfig) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(false);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));
        assertThat(factory.create()).isNull();
    }

    @Test
    void createShouldReturnDataSource() {
        final var config = (GitHubVulnDataSourceConfig) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        dataSource.close();
    }

}