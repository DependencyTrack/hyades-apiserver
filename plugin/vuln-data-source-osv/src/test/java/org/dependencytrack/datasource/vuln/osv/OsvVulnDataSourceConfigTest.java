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

import org.dependencytrack.plugin.testing.AbstractRuntimeConfigTest;
import org.jspecify.annotations.NonNull;

class OsvVulnDataSourceConfigTest extends AbstractRuntimeConfigTest {

    protected OsvVulnDataSourceConfigTest() {
        super(OsvVulnDataSourceConfig.class);
    }

    @Override
    protected @NonNull String getExpectedJsonSchema() {
        return /* language=JSON */ """
                {
                  "$schema": "https://json-schema.org/draft/2020-12/schema",
                  "type": "object",
                  "properties": {
                    "enabled": {
                      "type": "boolean"
                    },
                    "aliasSyncEnabled": {
                      "type": "boolean"
                    },
                    "dataUrl": {
                      "type": "string",
                      "minLength": 1,
                      "format": "uri"
                    },
                    "ecosystems": {
                      "minItems": 1,
                      "uniqueItems": true,
                      "type": "array",
                      "items": {
                        "type": "string"
                      }
                    }
                  },
                  "additionalProperties": false,
                  "required": [
                    "enabled",
                    "aliasSyncEnabled",
                    "dataUrl",
                    "ecosystems"
                  ]
                }
                """;
    }

}