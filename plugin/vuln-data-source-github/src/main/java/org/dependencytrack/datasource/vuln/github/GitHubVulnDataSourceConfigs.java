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

import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

/**
 * @since 5.7.0
 */
public final class GitHubVulnDataSourceConfigs {

    public static final RuntimeConfigDefinition<Boolean> CONFIG_ENABLED;
    static final RuntimeConfigDefinition<Boolean> CONFIG_ALIAS_SYNC_ENABLED;
    static final RuntimeConfigDefinition<URL> CONFIG_API_URL;
    static final RuntimeConfigDefinition<String> CONFIG_API_TOKEN;

    static {
        final URL defaultApiUrl;
        try {
            defaultApiUrl = URI.create("https://api.github.com/graphql").toURL();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Failed to parse default API URL", e);
        }

        CONFIG_ENABLED = new RuntimeConfigDefinition<>(
                "enabled",
                "Whether the GitHub Advisories data source should be enabled",
                ConfigTypes.BOOLEAN,
                /* defaultValue */ false,
                /* isRequired */ false,
                /* isSecret */ false);
        CONFIG_ALIAS_SYNC_ENABLED = new RuntimeConfigDefinition<>(
                "alias.sync.enabled",
                "Whether to include alias information in vulnerability data",
                ConfigTypes.BOOLEAN,
                /* defaultValue */ false,
                /* isRequired */ false,
                /* isSecret */ false);
        CONFIG_API_URL = new RuntimeConfigDefinition<>(
                "api.url",
                "Base URL of GitHub's GraphQL API",
                ConfigTypes.URL,
                /* defaultValue */ defaultApiUrl,
                /* isRequired */ true,
                /* isSecret */ false);
        CONFIG_API_TOKEN = new RuntimeConfigDefinition<>(
                "api.token",
                "Access token to authenticate with the GitHub API",
                ConfigTypes.STRING,
                /* defaultValue */ null,
                /* isRequired */ false,
                /* isSecret */ true);
    }

    private GitHubVulnDataSourceConfigs() {
    }

}
