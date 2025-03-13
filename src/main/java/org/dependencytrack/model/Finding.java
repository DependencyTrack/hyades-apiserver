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
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.parser.common.resolver.CweResolver;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;


/**
 * The Finding object is a metadata/value object that combines data from multiple tables. The object can
 * only be queried on, not updated or deleted. Modifications to data in the Finding object need to be made
 * to the original source object needing modified.
 *
 * @since 3.1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Finding implements Serializable {

    private static final long serialVersionUID = 5313521394432526986L;

    private final UUID project;
    private final Map<String, Object> component = new LinkedHashMap<>();
    private final Map<String, Object> vulnerability = new LinkedHashMap<>();
    private final Map<String, Object> analysis = new LinkedHashMap<>();
    private final Map<String, Object> attribution = new LinkedHashMap<>();

    public Finding(Project projectToMap, Component componentToMap, Vulnerability vulnToMap, Epss epss, Analysis analysisToMap, FindingAttribution attributionToMap) {
        this.project = projectToMap.getUuid();
        optValue(component, "uuid", componentToMap.getUuid());
        optValue(component, "name", componentToMap.getName());
        optValue(component, "group", componentToMap.getGroup());
        optValue(component, "version", componentToMap.getVersion());
        if (componentToMap.getPurl() != null) {
            optValue(component, "purl", componentToMap.getPurl().canonicalize());
        }
        optValue(component, "cpe", componentToMap.getCpe());
        optValue(component, "project", projectToMap.getUuid().toString());

        optValue(vulnerability, "uuid", vulnToMap.getUuid());
        optValue(vulnerability, "source", vulnToMap.getSource());
        optValue(vulnerability, "vulnId", vulnToMap.getVulnId());
        optValue(vulnerability, "title", vulnToMap.getTitle());
        optValue(vulnerability, "subtitle", vulnToMap.getSubTitle());
        optValue(vulnerability, "description", vulnToMap.getDescription());
        optValue(vulnerability, "recommendation", vulnToMap.getRecommendation());
        final Severity severity = vulnToMap.getSeverity();
        optValue(vulnerability, "cvssV2BaseScore", vulnToMap.getCvssV2BaseScore());
        optValue(vulnerability, "cvssV3BaseScore", vulnToMap.getCvssV3BaseScore());
        optValue(vulnerability, "cvssV2Vector", vulnToMap.getCvssV2Vector());
        optValue(vulnerability, "cvssV3Vector", vulnToMap.getCvssV3Vector());
        optValue(vulnerability, "owaspLikelihoodScore", vulnToMap.getOwaspRRLikelihoodScore());
        optValue(vulnerability, "owaspTechnicalImpactScore", vulnToMap.getOwaspRRTechnicalImpactScore());
        optValue(vulnerability, "owaspBusinessImpactScore", vulnToMap.getOwaspRRBusinessImpactScore());
        optValue(vulnerability, "owaspRRVector", vulnToMap.getOwaspRRVector());
        optValue(vulnerability, "severity", severity.name());
        optValue(vulnerability, "severityRank", severity.ordinal());
        optValue(vulnerability, "epssScore", epss.getScore());
        optValue(vulnerability, "epssPercentile", epss.getPercentile());
        optValue(vulnerability, "cwes", vulnToMap.getCwes());
        addVulnerabilityAliases(vulnToMap.getAliases());
        optValue(attribution, "analyzerIdentity", attributionToMap.getAnalyzerIdentity());
        optValue(attribution, "attributedOn", attributionToMap.getAttributedOn());
        optValue(attribution, "alternateIdentifier", attributionToMap.getAlternateIdentifier());
        optValue(attribution, "referenceUrl", attributionToMap.getReferenceUrl());

        optValue(analysis, "state", analysisToMap.getAnalysisState());
        optValue(analysis, "isSuppressed", analysisToMap.isSuppressed(), false);
        optValue(vulnerability, "published", vulnToMap.getPublished());
        optValue(component, "projectName", projectToMap.getName());
        optValue(component, "projectVersion", projectToMap.getVersion());
    }

    public Map<String, Object> getComponent() {
        return component;
    }

    public Map<String, Object> getVulnerability() {
        return vulnerability;
    }

    public Map<String, Object> getAnalysis() {
        return analysis;
    }

    public Map<String, Object> getAttribution() {
        return attribution;
    }

    private void optValue(Map<String, Object> map, String key, Object value, boolean defaultValue) {
        if (value == null) {
            map.put(key, defaultValue);
        } else {
            map.put(key, value);
        }
    }

    private void optValue(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    static List<Cwe> getCwes(final Object value) {
        if (value instanceof final String cweIds) {
            if (StringUtils.isBlank(cweIds)) {
                return null;
            }
            final List<Cwe> cwes = new ArrayList<>();
            for (final String s : cweIds.split(",")) {
                if (StringUtils.isNumeric(s)) {
                    final Cwe cwe = CweResolver.getInstance().lookup(Integer.valueOf(s));
                    if (cwe != null) {
                        cwes.add(cwe);
                    }
                }
            }
            if (cwes.isEmpty()) {
                return null;
            }
            return cwes;
        } else {
            return null;
        }
    }

    public String getMatrix() {
        return project.toString() + ":" + component.get("uuid") + ":" + vulnerability.get("uuid");
    }

    public void addVulnerabilityAliases(List<VulnerabilityAlias> aliases) {
        final Set<Map<String, String>> uniqueAliases = new HashSet<>();
        if (aliases != null) {
            for (final VulnerabilityAlias alias : aliases) {
                Map<String,String> map = new HashMap<>();
                if (alias.getCveId() != null && !alias.getCveId().isBlank()) {
                    map.put("cveId", alias.getCveId());
                }
                if (alias.getGhsaId() != null && !alias.getGhsaId().isBlank()) {
                    map.put("ghsaId", alias.getGhsaId());
                }
                if (alias.getSonatypeId() != null && !alias.getSonatypeId().isBlank()) {
                    map.put("sonatypeId", alias.getSonatypeId());
                }
                if (alias.getOsvId() != null && !alias.getOsvId().isBlank()) {
                    map.put("osvId", alias.getOsvId());
                }
                if (alias.getSnykId() != null && !alias.getSnykId().isBlank()) {
                    map.put("snykId", alias.getSnykId());
                }
                if (alias.getVulnDbId() != null && !alias.getVulnDbId().isBlank()) {
                    map.put("vulnDbId", alias.getVulnDbId());
                }
                uniqueAliases.add(map);
            }
        }
        vulnerability.put("aliases", uniqueAliases);
    }

}