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

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.plugin.api.config.RuntimeConfig;

/**
 * @since 5.7.0
 */
@Schema(additionalProperties = Schema.AdditionalPropertiesValue.FALSE)
@JsonPropertyOrder(value = {
        "enabled",
        "aliasSyncEnabled",
        "apiUrl",
        "apiToken"
})
public final class GitHubVulnDataSourceConfig implements RuntimeConfig {

    @Schema(
            description = "Whether the GitHub Advisories data source should be enabled",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private boolean enabled;

    @Schema(
            description = "Whether to include alias information in vulnerability data",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private boolean aliasSyncEnabled;

    @Schema(
            description = "Base URL of GitHub's GraphQL API",
            minLength = 1,
            format = "uri",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String apiUrl;

    @Schema(
            description = """
                    Access token to authenticate with the GitHub API. \
                    The token is only required for authentication and does \
                    not require any permissions. Both fine-grained and classic \
                    access tokens work.""",
            pattern = "^(ghp_|github_pat_).+$",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String apiToken;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isAliasSyncEnabled() {
        return aliasSyncEnabled;
    }

    public void setAliasSyncEnabled(final boolean aliasSyncEnabled) {
        this.aliasSyncEnabled = aliasSyncEnabled;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(final String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public String getApiToken() {
        return apiToken;
    }

    public void setApiToken(final String apiToken) {
        this.apiToken = apiToken;
    }

}
