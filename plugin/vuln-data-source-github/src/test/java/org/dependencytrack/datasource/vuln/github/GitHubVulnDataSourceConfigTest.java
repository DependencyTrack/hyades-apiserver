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

import org.dependencytrack.plugin.testing.AbstractRuntimeConfigTest;
import org.jspecify.annotations.NonNull;

class GitHubVulnDataSourceConfigTest extends AbstractRuntimeConfigTest {

    protected GitHubVulnDataSourceConfigTest() {
        super(GitHubVulnDataSourceConfig.class);
    }

    @Override
    protected @NonNull String getExpectedJsonSchema() {
        return /* language=JSON */ """
                {
                  "$schema": "https://json-schema.org/draft/2020-12/schema",
                  "type": "object",
                  "properties": {
                    "enabled": {
                      "type": "boolean",
                      "description": "Whether the GitHub Advisories data source should be enabled"
                    },
                    "aliasSyncEnabled": {
                      "type": "boolean",
                      "description": "Whether to include alias information in vulnerability data"
                    },
                    "apiUrl": {
                      "type": "string",
                      "description": "Base URL of GitHub's GraphQL API",
                      "format": "uri",
                      "minLength": 1
                    },
                    "apiToken": {
                      "type": "string",
                      "description": "Access token to authenticate with the GitHub API. The token is only required for authentication and does not require any permissions. Both fine-grained and classic access tokens work.",
                      "pattern": "^(ghp_|github_pat_).+$"
                    }
                  },
                  "additionalProperties": false,
                  "required": [
                    "enabled",
                    "aliasSyncEnabled",
                    "apiUrl",
                    "apiToken"
                  ]
                }
                """;
    }

}