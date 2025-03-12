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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The GroupedFinding object is a metadata/value object that combines data from multiple tables. The object can
 * only be queried on, not updated or deleted. Modifications to data in the GroupedFinding object need to be made
 * to the original source object needing modified.
 *
 * @since 4.8.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GroupedFinding implements Serializable {

    private static final long serialVersionUID = 2246518534279822243L;

    private Map<String, Object> vulnerability = new LinkedHashMap<>();
    private Map<String, Object> attribution = new LinkedHashMap<>();

    public GroupedFinding(Vulnerability vulnToMap, FindingAttribution attributionToMap) {
        optValue(vulnerability, "source", vulnToMap.getSource());
        optValue(vulnerability, "vulnId", vulnToMap.getVulnId());
        optValue(vulnerability, "title", vulnToMap.getTitle());
        optValue(vulnerability, "severity", vulnToMap.getSeverity());
        optValue(vulnerability, "cvssV2BaseScore", vulnToMap.getCvssV2BaseScore());
        optValue(vulnerability, "cvssV3BaseScore", vulnToMap.getCvssV3BaseScore());
        optValue(attribution, "analyzerIdentity", attributionToMap.getAnalyzerIdentity());
        optValue(vulnerability, "published", vulnToMap.getPublished());
        optValue(vulnerability, "cwes", vulnToMap.getCwes());
        optValue(vulnerability, "affectedProjectCount", vulnToMap.getAffectedProjectCount());
    }

    public Map getVulnerability() {
        return vulnerability;
    }

    public Map getAttribution() {
        return attribution;
    }

    private void optValue(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }
}