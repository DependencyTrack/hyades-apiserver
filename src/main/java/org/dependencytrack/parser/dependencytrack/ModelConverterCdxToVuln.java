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
package org.dependencytrack.parser.dependencytrack;

import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.ScoreMethod;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.VulnerabilityRating;
import org.cyclonedx.proto.v1_6.VulnerabilityReference;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.vulnanalysis.v1.Scanner;
import org.dependencytrack.util.VulnerabilityUtil;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;
import us.springett.owasp.riskrating.MissingFactorException;
import us.springett.owasp.riskrating.OwaspRiskRating;

import java.math.BigDecimal;
import java.sql.Date;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_OWASP;

public final class ModelConverterCdxToVuln {

    static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";

    public static Vulnerability convert(final QueryManager qm, final Bom bom,
                                        final org.cyclonedx.proto.v1_6.Vulnerability cycloneVuln,
                                        boolean isAliasSyncEnabled) {
        if (cycloneVuln == null) {
            return null;
        }
        final Vulnerability vuln = new Vulnerability();
        if (cycloneVuln.hasId()) {
            vuln.setSource(extractSource(cycloneVuln.getId(), cycloneVuln.getSource()));
        }
        vuln.setVulnId(cycloneVuln.getId());
        if (cycloneVuln.getPropertiesCount() != 0) {
            var titleProperty = cycloneVuln.getProperties(0);
            if (titleProperty.getName().equals(TITLE_PROPERTY_NAME) && titleProperty.hasValue()) {
                vuln.setTitle(StringUtils.abbreviate(titleProperty.getValue(), 255));
            }
        }
        if (cycloneVuln.hasDescription()) {
            vuln.setDescription(cycloneVuln.getDescription());
        }
        if (cycloneVuln.hasDetail()) {
            vuln.setDetail(cycloneVuln.getDetail());
        }
        if (cycloneVuln.hasRecommendation()) {
            vuln.setRecommendation(cycloneVuln.getRecommendation());
        }
        if (cycloneVuln.hasPublished()) {
            vuln.setPublished(Date.from(Instant.ofEpochSecond(cycloneVuln.getPublished().getSeconds())));
        }
        if (cycloneVuln.hasUpdated()) {
            vuln.setUpdated(Date.from(Instant.ofEpochSecond(cycloneVuln.getUpdated().getSeconds())));
        }
        if (cycloneVuln.hasCreated()) {
            vuln.setCreated(Date.from(Instant.ofEpochSecond(cycloneVuln.getCreated().getSeconds())));
        }
        if (cycloneVuln.hasCredits()) {
            vuln.setCredits(String.join(", ", cycloneVuln.getCredits().toString()));
        }

        // external links
        final StringBuilder sb = new StringBuilder();
        if (!bom.getExternalReferencesList().isEmpty()) {
            bom.getExternalReferencesList().forEach(externalReference -> {
                sb.append("* [").append(externalReference.getUrl()).append("](").append(externalReference.getUrl()).append(")\n");
            });
            vuln.setReferences(sb.toString());
        }
        if (!cycloneVuln.getAdvisoriesList().isEmpty()) {
            cycloneVuln.getAdvisoriesList().forEach(advisory -> {
                sb.append("* [").append(advisory.getUrl()).append("](").append(advisory.getUrl()).append(")\n");
            });
            vuln.setReferences(sb.toString());
        }

        cycloneVuln.getCwesList().stream()
                .map(CweResolver.getInstance()::lookup)
                .filter(Objects::nonNull)
                .forEach(vuln::addCwe);

        final List<VulnerabilityRating> prioritizedRatings = cycloneVuln.getRatingsList().stream()
                .sorted(compareRatings(cycloneVuln.getSource()))
                .toList();

        // Apply ratings in their prioritized order, ensuring that only one rating per method is applied.
        // Because DT does not track CVSSv3 and CVSSv3.1 separately, they are considered the same here.
        final var appliedMethods = new HashSet<ScoreMethod>();
        for (final VulnerabilityRating rating : prioritizedRatings) {
            if (!rating.hasMethod()) {
                // We'll not be able to populate Vulnerability fields correctly if
                // we don't know what method was used to produce the rating.
                continue;
            }

            if (!appliedMethods.contains(SCORE_METHOD_CVSSV3)
                    && (rating.getMethod().equals(SCORE_METHOD_CVSSV3) || rating.getMethod().equals(SCORE_METHOD_CVSSV31))) {
                vuln.setCvssV3Vector(trimToNull(rating.getVector()));
                vuln.setCvssV3BaseScore(BigDecimal.valueOf(rating.getScore()));
                if (rating.hasVector()) {
                    final Cvss cvss = Cvss.fromVector(rating.getVector());
                    final Score score = cvss.calculateScore();
                    vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                    vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                    if (rating.getScore() == 0.0) {
                        vuln.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                    }
                }
                appliedMethods.add(SCORE_METHOD_CVSSV3);
            }
            if (!appliedMethods.contains(SCORE_METHOD_CVSSV2) && rating.getMethod().equals(SCORE_METHOD_CVSSV2)) {
                vuln.setCvssV2Vector(trimToNull(rating.getVector()));
                vuln.setCvssV2BaseScore(BigDecimal.valueOf(rating.getScore()));
                if (rating.hasVector()) {
                    final Cvss cvss = Cvss.fromVector(rating.getVector());
                    final Score score = cvss.calculateScore();
                    vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                    vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                    if (rating.getScore() == 0.0) {
                        vuln.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                    }
                }
                appliedMethods.add(SCORE_METHOD_CVSSV2);
            }
            if (!appliedMethods.contains(SCORE_METHOD_OWASP) && rating.getMethod().equals(ScoreMethod.SCORE_METHOD_OWASP)) {
                try {
                    final OwaspRiskRating orr = OwaspRiskRating.fromVector(rating.getVector());
                    final us.springett.owasp.riskrating.Score orrScore = orr.calculateScore();
                    vuln.setOwaspRRVector(trimToNull(rating.getVector()));
                    vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(orrScore.getLikelihoodScore()));
                    vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(orrScore.getBusinessImpactScore()));
                    vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(orrScore.getTechnicalImpactScore()));
                    appliedMethods.add(SCORE_METHOD_OWASP);
                } catch (IllegalArgumentException | MissingFactorException e) {
                    // Ignore
                }
            }
        }
        vuln.setSeverity(VulnerabilityUtil.getSeverity(
                vuln.getSeverity(),
                vuln.getCvssV2BaseScore(),
                vuln.getCvssV3BaseScore(),
                vuln.getOwaspRRLikelihoodScore(),
                vuln.getOwaspRRTechnicalImpactScore(),
                vuln.getOwaspRRBusinessImpactScore()
        ));

        // There can be cases where ratings do not have a known method, and the source only assigned
        // a severity. Such ratings are inferior to those with proper method and vector, but we'll use
        // them if no better option is available.
        if (appliedMethods.isEmpty() && vuln.getSeverity() == Severity.UNASSIGNED) {
            // Pick the first rating that provides a severity, and apply that.
            prioritizedRatings.stream()
                    .filter(VulnerabilityRating::hasSeverity)
                    .findFirst()
                    .map(rating -> switch (rating.getSeverity()) {
                        case SEVERITY_CRITICAL -> Severity.CRITICAL;
                        case SEVERITY_HIGH -> Severity.HIGH;
                        case SEVERITY_MEDIUM -> Severity.MEDIUM;
                        case SEVERITY_LOW -> Severity.LOW;
                        default -> Severity.UNASSIGNED;
                    })
                    .ifPresent(vuln::setSeverity);
        }

        if (isAliasSyncEnabled && !cycloneVuln.getReferencesList().isEmpty()) {
            vuln.setAliases(cycloneVuln.getReferencesList().stream()
                    .map(alias -> convert(cycloneVuln, alias)).toList());
        }

        // EPSS is an additional enrichment that no scanner currently provides.
        // TODO: Add mapping of EPSS score and percentile when needed.

        return vuln;
    }

    private static VulnerabilityAlias convert(final org.cyclonedx.proto.v1_6.Vulnerability cycloneVuln,
                                              final VulnerabilityReference cycloneAlias) {
        final var alias = new VulnerabilityAlias();
        switch (cycloneVuln.getSource().getName()) {
            case "GITHUB" -> alias.setGhsaId(cycloneVuln.getId());
            case "INTERNAL" -> alias.setInternalId(cycloneVuln.getId());
            case "NVD" -> alias.setCveId(cycloneVuln.getId());
            case "OSSINDEX" -> alias.setSonatypeId(cycloneVuln.getId());
            case "OSV" -> alias.setOsvId(cycloneVuln.getId());
            case "SNYK" -> alias.setSnykId(cycloneVuln.getId());
            case "VULNDB" -> alias.setVulnDbId(cycloneVuln.getId());
            case "CSAF" -> alias.setCsafId(cycloneVuln.getId());
            // Source of the vulnerability itself has been validated before,
            // so this scenario is highly unlikely to ever happen. Including
            // it here to make linters happy.
            default ->
                    throw new IllegalArgumentException("Invalid vulnerability source %s".formatted(cycloneVuln.getSource().getName()));
        }
        switch (cycloneAlias.getSource().getName()) {
            case "GITHUB" -> alias.setGhsaId(cycloneAlias.getId());
            case "INTERNAL" -> alias.setInternalId(cycloneAlias.getId());
            case "NVD" -> alias.setCveId(cycloneAlias.getId());
            case "OSSINDEX" -> alias.setSonatypeId(cycloneAlias.getId());
            case "OSV" -> alias.setOsvId(cycloneAlias.getId());
            case "SNYK" -> alias.setSnykId(cycloneAlias.getId());
            case "VULNDB" -> alias.setVulnDbId(cycloneAlias.getId());
            case "CSAF" -> alias.setCsafId(cycloneAlias.getId());
            default -> throw new IllegalArgumentException("Invalid source %s for alias %s"
                    .formatted(cycloneAlias.getSource().getName(), cycloneAlias.getId()));
        }
        return alias;
    }


    public static Severity calculateSeverity(Bom bom) {
        if (bom.getVulnerabilitiesCount() > 0
                && bom.getVulnerabilities(0).getRatingsCount() > 0) {
            org.cyclonedx.proto.v1_6.Severity severity =
                    bom.getVulnerabilities(0).getRatings(0).getSeverity();
            final VulnerabilityRating rating = bom.getVulnerabilities(0).getRatings(0);
            if (rating.hasSeverity()) {
                return switch (rating.getSeverity()) {
                    case SEVERITY_CRITICAL -> Severity.CRITICAL;
                    case SEVERITY_HIGH -> Severity.HIGH;
                    case SEVERITY_MEDIUM -> Severity.MEDIUM;
                    case SEVERITY_LOW -> Severity.LOW;
                    default -> Severity.UNASSIGNED;
                };
            }
        }
        return Severity.UNASSIGNED;
    }

    public static Vulnerability.Source extractSource(String vulnId, Source source) {
        final String sourceId = vulnId.split("-")[0];
        return switch (sourceId) {
            case "GHSA" -> Vulnerability.Source.GITHUB;
            case "CVE" -> Vulnerability.Source.NVD;
            case "CSAF" -> Vulnerability.Source.CSAF;
            default -> source != null ? Vulnerability.Source.valueOf(source.getName()) : Vulnerability.Source.INTERNAL;
        };
    }

    public static AnalyzerIdentity convert(final Scanner scanner) {
        return switch (scanner) {
            case SCANNER_INTERNAL -> AnalyzerIdentity.INTERNAL_ANALYZER;
            case SCANNER_OSSINDEX -> AnalyzerIdentity.OSSINDEX_ANALYZER;
            case SCANNER_SNYK -> AnalyzerIdentity.SNYK_ANALYZER;
            case SCANNER_CSAF -> AnalyzerIdentity.CSAF_ANALYZER;
            default -> AnalyzerIdentity.NONE;
        };
    }

    /**
     * Determines the priority of {@link ScoreMethod}s, as used by {@link #compareRatings(Source)}.
     * <p>
     * A lower number signals a higher priority.
     *
     * @return Priority of the {@link ScoreMethod}
     */
    private static int scoreMethodPriority(final ScoreMethod method) {
        return switch (method) {
            case SCORE_METHOD_CVSSV31 -> 0;
            case SCORE_METHOD_CVSSV3 -> 1;
            case SCORE_METHOD_CVSSV2 -> 2;
            case SCORE_METHOD_OWASP -> 3;
            default -> 999;
        };
    }

    /**
     * Vulnerabilities can have multiple risk ratings of the same type, and by multiple sources,
     * but DT currently only supports one per type.
     */
    private static Comparator<VulnerabilityRating> compareRatings(final Source vulnSource) {
        return (left, right) -> {
            // Prefer ratings from the vulnerability's authoritative source.
            if (left.getSource().getName().equals(vulnSource.getName()) && !right.getSource().getName().equals(vulnSource.getName())) {
                return -1; // left wins
            } else if (!left.getSource().getName().equals(vulnSource.getName()) && right.getSource().getName().equals(vulnSource.getName())) {
                return 1; // right wins
            }

            // Prefer specified method over no / unknown methods.
            if (left.hasMethod() && !right.hasMethod()) {
                return -1; // left wins
            } else if (!left.hasMethod() && right.hasMethod()) {
                return 1; // right wins
            }

            // Prefer ratings with vector
            if (left.hasVector() && !right.hasVector()) {
                return -1; // left wins
            } else if (!left.hasVector() && right.hasVector()) {
                return 1; // right wins
            }

            // Leave the final decision up to the respective method's priorities.
            return Integer.compare(
                    scoreMethodPriority(left.getMethod()),
                    scoreMethodPriority(right.getMethod())
            );
        };
    }
}
