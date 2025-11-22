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

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.plugin.api.config.RuntimeConfig;

import java.util.Set;

/**
 * @since 5.7.0
 */
@Schema(additionalProperties = Schema.AdditionalPropertiesValue.FALSE)
@JsonPropertyOrder(value = {
        "enabled",
        "aliasSyncEnabled",
        "dataUrl",
        "ecosystems"
})
public final class OsvVulnDataSourceConfig implements RuntimeConfig {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private boolean enabled;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private boolean aliasSyncEnabled;

    @Schema(format = "uri", minLength = 1, requiredMode = Schema.RequiredMode.REQUIRED)
    private String dataUrl;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    @ArraySchema(uniqueItems = true, minItems = 1)
    private Set<String> ecosystems;

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

    public String getDataUrl() {
        return dataUrl;
    }

    public void setDataUrl(final String dataUrl) {
        this.dataUrl = dataUrl;
    }

    public Set<String> getEcosystems() {
        return ecosystems;
    }

    public void setEcosystems(final Set<String> ecosystems) {
        this.ecosystems = ecosystems;
    }

}
