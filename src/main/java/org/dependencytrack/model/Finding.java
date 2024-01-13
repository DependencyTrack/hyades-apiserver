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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.json.JSONPropertyName;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
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

    private final Component component;
    private final Vulnerability vulnerability;
    private final Analysis analysis;
    private final Attribution attribution;

    public Finding(final Analysis analysis, final Attribution attribution,
                   final Component component, final Vulnerability vulnerability) {
        this.analysis = analysis;
        this.attribution = attribution;
        this.component = component;
        this.vulnerability = vulnerability;
    }

    public Component getComponent() {
        return component;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public Analysis getAnalysis() {
        return analysis;
    }

    public Attribution getAttribution() {
        return attribution;
    }

    @SuppressWarnings("unused") // Called by JSON serializers.
    public String getMatrix() {
        return component.getProject() + ":" + component.getUuid() + ":" + vulnerability.getUuid();
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Analysis {

        private AnalysisState state;

        private Boolean isSuppressed;

        public AnalysisState getState() {
            return state;
        }

        public void setState(final AnalysisState state) {
            this.state = state;
        }

        @JsonGetter("isSuppressed") // For Jackson; Used to serialize REST API responses.
        @JSONPropertyName("isSuppressed") // For JSON-Java; Used for Finding Packaging Format (FPF).
        public Boolean isSuppressed() {
            return isSuppressed;
        }

        public void setSuppressed(final Boolean suppressed) {
            isSuppressed = suppressed;
        }

    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Attribution {

        private AnalyzerIdentity analyzerIdentity;
        private Date attributedOn;
        private String alternateIdentifier;
        private String referenceUrl;

        public AnalyzerIdentity getAnalyzerIdentity() {
            return analyzerIdentity;
        }

        public void setAnalyzerIdentity(final AnalyzerIdentity analyzerIdentity) {
            this.analyzerIdentity = analyzerIdentity;
        }

        public Date getAttributedOn() {
            return attributedOn;
        }

        public void setAttributedOn(final Date attributedOn) {
            this.attributedOn = attributedOn;
        }

        public String getAlternateIdentifier() {
            return alternateIdentifier;
        }

        public void setAlternateIdentifier(final String alternateIdentifier) {
            this.alternateIdentifier = alternateIdentifier;
        }

        public String getReferenceUrl() {
            return referenceUrl;
        }

        public void setReferenceUrl(final String referenceUrl) {
            this.referenceUrl = referenceUrl;
        }

    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Component {

        private UUID project;
        private UUID uuid;
        private String group;
        private String name;
        private String version;
        private String latestVersion;
        private String cpe;
        private String purl;

        public UUID getProject() {
            return project;
        }

        public void setProject(final UUID project) {
            this.project = project;
        }

        public UUID getUuid() {
            return uuid;
        }

        public void setUuid(final UUID uuid) {
            this.uuid = uuid;
        }

        public String getGroup() {
            return group;
        }

        public void setGroup(final String group) {
            this.group = group;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(final String version) {
            this.version = version;
        }

        public String getLatestVersion() {
            return latestVersion;
        }

        public void setLatestVersion(final String latestVersion) {
            this.latestVersion = latestVersion;
        }

        public String getCpe() {
            return cpe;
        }

        public void setCpe(final String cpe) {
            this.cpe = cpe;
        }

        public String getPurl() {
            return purl;
        }

        public void setPurl(final String purl) {
            this.purl = purl;
        }

    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Vulnerability {

        private UUID uuid;
        private String vulnId;
        private org.dependencytrack.model.Vulnerability.Source source;
        private String title;
        private String subtitle;
        private String description;
        private String recommendation;
        private Double cvssV2BaseScore;
        private Double cvssV3BaseScore;
        private Double owaspBusinessImpactScore;
        private Double owaspLikelihoodScore;
        private Double owaspTechnicalImpactScore;
        private Severity severity;
        private Integer severityRank;
        private Double epssScore;
        private Double epssPercentile;
        private List<Cwe> cwes;
        private Integer cweId;
        private String cweName;
        private Set<Map<String, String>> aliases;

        public UUID getUuid() {
            return uuid;
        }

        public void setUuid(final UUID uuid) {
            this.uuid = uuid;
        }

        public String getVulnId() {
            return vulnId;
        }

        public void setVulnId(final String vulnId) {
            this.vulnId = vulnId;
        }

        public org.dependencytrack.model.Vulnerability.Source getSource() {
            return source;
        }

        public void setSource(final org.dependencytrack.model.Vulnerability.Source source) {
            this.source = source;
        }

        public String getTitle() {
            return title;
        }

        public void setTitle(final String title) {
            this.title = title;
        }

        public String getSubtitle() {
            return subtitle;
        }

        public void setSubtitle(final String subtitle) {
            this.subtitle = subtitle;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(final String description) {
            this.description = description;
        }

        public String getRecommendation() {
            return recommendation;
        }

        public void setRecommendation(final String recommendation) {
            this.recommendation = recommendation;
        }

        public Double getCvssV2BaseScore() {
            return cvssV2BaseScore;
        }

        public void setCvssV2BaseScore(final Double cvssV2BaseScore) {
            this.cvssV2BaseScore = cvssV2BaseScore;
        }

        public Double getCvssV3BaseScore() {
            return cvssV3BaseScore;
        }

        public void setCvssV3BaseScore(final Double cvssV3BaseScore) {
            this.cvssV3BaseScore = cvssV3BaseScore;
        }

        public Double getOwaspBusinessImpactScore() {
            return owaspBusinessImpactScore;
        }

        public void setOwaspBusinessImpactScore(final Double owaspBusinessImpactScore) {
            this.owaspBusinessImpactScore = owaspBusinessImpactScore;
        }

        public Double getOwaspLikelihoodScore() {
            return owaspLikelihoodScore;
        }

        public void setOwaspLikelihoodScore(final Double owaspLikelihoodScore) {
            this.owaspLikelihoodScore = owaspLikelihoodScore;
        }

        public Double getOwaspTechnicalImpactScore() {
            return owaspTechnicalImpactScore;
        }

        public void setOwaspTechnicalImpactScore(final Double owaspTechnicalImpactScore) {
            this.owaspTechnicalImpactScore = owaspTechnicalImpactScore;
        }

        public Severity getSeverity() {
            return severity;
        }

        public void setSeverity(final Severity severity) {
            this.severity = severity;
            this.severityRank = severity.ordinal();
        }

        public Integer getSeverityRank() {
            return severityRank;
        }

        public Double getEpssScore() {
            return epssScore;
        }

        public void setEpssScore(final Double epssScore) {
            this.epssScore = epssScore;
        }

        public Double getEpssPercentile() {
            return epssPercentile;
        }

        public void setEpssPercentile(final Double epssPercentile) {
            this.epssPercentile = epssPercentile;
        }

        public List<Cwe> getCwes() {
            return cwes;
        }

        public void setCwes(final List<Cwe> cwes) {
            this.cwes = cwes;
        }

        public Integer getCweId() {
            return cweId;
        }

        public void setCweId(final Integer cweId) {
            this.cweId = cweId;
        }

        public String getCweName() {
            return cweName;
        }

        public void setCweName(final String cweName) {
            this.cweName = cweName;
        }

        public Set<Map<String, String>> getAliases() {
            return aliases;
        }

        public void setAliases(final Set<Map<String, String>> aliases) {
            this.aliases = aliases;
        }

        public void addVulnerabilityAliases(List<VulnerabilityAlias> aliases) {
            final Set<Map<String, String>> uniqueAliases = new HashSet<>();
            for (final VulnerabilityAlias alias : aliases) {
                Map<String, String> map = new HashMap<>();
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
            this.aliases = uniqueAliases;
        }
    }

}
