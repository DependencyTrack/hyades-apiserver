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

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.google.protobuf.util.Timestamps;
import io.github.nscuro.versatile.Constraint;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import io.github.nscuro.versatile.version.VersioningScheme;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.ScoreMethod;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.VulnerabilityAffectedVersions;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.cyclonedx.proto.v1_6.VulnerabilityRating;
import org.cyclonedx.proto.v1_6.VulnerabilityReference;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.proto.vulnanalysis.v1.Scanner;
import org.dependencytrack.util.VulnerabilityUtil;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;
import us.springett.owasp.riskrating.MissingFactorException;
import us.springett.owasp.riskrating.OwaspRiskRating;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_OWASP;

public final class BovModelConverter {

    private static final Logger LOGGER = Logger.getLogger(BovModelConverter.class);
    static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";

    private BovModelConverter() {
    }

    public static Vulnerability convert(
            final Bom bov,
            final org.cyclonedx.proto.v1_6.Vulnerability cdxVuln,
            final boolean isAliasSyncEnabled) {
        if (cdxVuln == null) {
            return null;
        }

        final var vuln = new Vulnerability();
        if (cdxVuln.hasId()) {
            vuln.setSource(extractSource(cdxVuln.getId(), cdxVuln.getSource()));
        }
        vuln.setVulnId(cdxVuln.getId());
        if (cdxVuln.getPropertiesCount() != 0) {
            var titleProperty = cdxVuln.getProperties(0);
            if (titleProperty.getName().equals(TITLE_PROPERTY_NAME) && titleProperty.hasValue()) {
                vuln.setTitle(StringUtils.abbreviate(titleProperty.getValue(), 255));
            }
        }
        if (cdxVuln.hasDescription()) {
            vuln.setDescription(cdxVuln.getDescription());
        }
        if (cdxVuln.hasDetail()) {
            vuln.setDetail(cdxVuln.getDetail());
        }
        if (cdxVuln.hasRecommendation()) {
            vuln.setRecommendation(cdxVuln.getRecommendation());
        }
        if (cdxVuln.hasPublished()) {
            vuln.setPublished(new Date(Timestamps.toMillis(cdxVuln.getPublished())));
        }
        if (cdxVuln.hasUpdated()) {
            vuln.setUpdated(new Date(Timestamps.toMillis(cdxVuln.getUpdated())));
        }
        if (cdxVuln.hasCreated()) {
            vuln.setCreated(new Date(Timestamps.toMillis(cdxVuln.getCreated())));
        }
        if (cdxVuln.hasCredits()) {
            vuln.setCredits(String.join(", ", cdxVuln.getCredits().toString()));
        }

        // external links
        final StringBuilder sb = new StringBuilder();
        if (!bov.getExternalReferencesList().isEmpty()) {
            bov.getExternalReferencesList().forEach(externalReference -> {
                sb.append("* [").append(externalReference.getUrl()).append("](").append(externalReference.getUrl()).append(")\n");
            });
            vuln.setReferences(sb.toString());
        }
        if (!cdxVuln.getAdvisoriesList().isEmpty()) {
            cdxVuln.getAdvisoriesList().forEach(advisory -> {
                sb.append("* [").append(advisory.getUrl()).append("](").append(advisory.getUrl()).append(")\n");
            });
            vuln.setReferences(sb.toString());
        }

        cdxVuln.getCwesList().stream()
                .map(CweResolver.getInstance()::lookup)
                .filter(Objects::nonNull)
                .forEach(vuln::addCwe);

        final List<VulnerabilityRating> prioritizedRatings = cdxVuln.getRatingsList().stream()
                .sorted(compareRatings(cdxVuln.getSource()))
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

        if (isAliasSyncEnabled && !cdxVuln.getReferencesList().isEmpty()) {
            vuln.setAliases(cdxVuln.getReferencesList().stream()
                    .map(alias -> convert(cdxVuln, alias)).toList());
        }

        // EPSS is an additional enrichment that no scanner currently provides.
        // TODO: Add mapping of EPSS score and percentile when needed.

        return vuln;
    }

    public static List<VulnerableSoftware> extractVulnerableSoftware(final Bom bov) {
        final org.cyclonedx.proto.v1_6.Vulnerability vuln = bov.getVulnerabilities(0);
        if (vuln.getAffectsCount() == 0) {
            return Collections.emptyList();
        }

        final var componentByBomRef = new HashMap<String, Component>();
        final var vsList = new ArrayList<VulnerableSoftware>();

        for (final VulnerabilityAffects bovVulnAffects : vuln.getAffectsList()) {
            final Component component = componentByBomRef.computeIfAbsent(
                    bovVulnAffects.getRef(),
                    bomRef -> bov.getComponentsList().stream()
                            .filter(c -> bomRef.equals(c.getBomRef()))
                            .findAny()
                            .orElse(null));
            if (component == null) {
                LOGGER.warn(
                        "No component in the BOV for %s is matching the BOM ref \"%s\" of the affects node; Skipping"
                                .formatted(vuln.getId(), bovVulnAffects.getRef()));
                continue;
            }

            for (final VulnerabilityAffectedVersions affectedVersions : bovVulnAffects.getVersionsList()) {
                if (affectedVersions.hasVersion()) {
                    vsList.addAll(convertAffectedVersion(vuln.getId(), affectedVersions.getVersion(), component));
                }
                if (affectedVersions.hasRange()) {
                    vsList.addAll(convertAffectedVersionRange(vuln.getId(), affectedVersions.getRange(), component));
                }
            }
        }

        return vsList.stream()
                .filter(distinctIgnoringDatastoreIdentity())
                .toList();
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

    private static List<VulnerableSoftware> convertAffectedVersion(
            final String vulnId,
            final String affectedVersion,
            final Component affectedComponent) {
        final var vsList = new ArrayList<VulnerableSoftware>(2);
        if (affectedComponent.hasCpe()) {
            try {
                final Cpe cpe = CpeParser.parse(affectedComponent.getCpe());

                final var vs = new VulnerableSoftware();
                vs.setCpe22(cpe.toCpe22Uri());
                vs.setCpe23(affectedComponent.getCpe());
                vs.setPart(cpe.getPart().getAbbreviation());
                vs.setVendor(cpe.getVendor());
                vs.setProduct(cpe.getProduct());
                vs.setVersion(affectedVersion);
                vs.setUpdate(cpe.getUpdate());
                vs.setEdition(cpe.getEdition());
                vs.setLanguage(cpe.getLanguage());
                vs.setSwEdition(cpe.getSwEdition());
                vs.setTargetSw(cpe.getTargetSw());
                vs.setTargetHw(cpe.getTargetHw());
                vs.setOther(cpe.getOther());
                vs.setVulnerable(true);

                vsList.add(vs);
            } catch (CpeParsingException e) {
                LOGGER.warn("Failed to parse CPE %s of %s; Skipping".formatted(
                        affectedComponent.getCpe(), vulnId), e);
            } catch (CpeEncodingException e) {
                LOGGER.warn("Failed to encode CPE %s of %s; Skipping".formatted(
                        affectedComponent.getCpe(), vulnId), e);
            }
        }

        if (affectedComponent.hasPurl()) {
            try {
                final PackageURL purl = new PackageURL(affectedComponent.getPurl());

                final var vs = new VulnerableSoftware();
                vs.setPurlType(purl.getType());
                vs.setPurlNamespace(purl.getNamespace());
                vs.setPurlName(purl.getName());
                vs.setPurl(purl.canonicalize());
                vs.setVersion(affectedVersion);
                vs.setVulnerable(true);

                vsList.add(vs);
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Failed to parse PURL from \"%s\" for %s; Skipping".formatted(
                        affectedComponent.getPurl(), vulnId), e);
            }
        }

        return vsList;
    }

    private static List<VulnerableSoftware> convertAffectedVersionRange(
            final String vulnId,
            final String affectedVersionRange,
            final Component affectedComponent) {
        final List<VulnerableSoftware> vsList = new ArrayList<>();
        final List<Vers> versList;
        try {
            versList = convertRangeToVersList(affectedVersionRange);
        } catch (VersException e) {
            LOGGER.warn(
                    "Failed to parse vers range from \"%s\" for %s".formatted(
                            affectedVersionRange, vulnId), e);
            return vsList;
        }

        for (final Vers vers : versList) {
            if (vers.constraints().isEmpty()) {
                LOGGER.debug(
                        "Vers range \"%s\" (parsed: %s) for %s does not contain any constraints; Skipping".formatted(
                                affectedVersionRange, vers, vulnId));
                continue;
            } else if (vers.constraints().size() == 1) {
                var versConstraint = vers.constraints().getFirst();
                if (versConstraint.comparator() == io.github.nscuro.versatile.Comparator.WILDCARD) {
                    // Wildcards in VulnerableSoftware can be represented via either:
                    //   * version=*, or
                    //   * versionStartIncluding=0
                    // We choose the more explicit first option.
                    vsList.addAll(convertAffectedVersion(vulnId, "*", affectedComponent));
                    continue;
                }
            }
            vsList.addAll(convertVersToVulnerableSoftware(vers, vulnId, affectedComponent));
        }
        return vsList;
    }

    static List<Vers> convertRangeToVersList(String range) {
        try {
            Vers parsedVers = Vers.parse(range);
            // Calling split to address ranges with all possible length of constraints
            return parsedVers.validate().split();
        } catch (VersException versException) {
            if (versException.getMessage().contains("invalid versioning scheme")) {
                // Fall back the invalid versioning scheme to 'generic' and reparse
                String[] rangeParts = range.split(":", 2);
                String[] versions = rangeParts[1].split("/", 2);
                var genericRange = rangeParts[0] + ":" + VersioningScheme.GENERIC.name().toLowerCase() + "/" + versions[1];
                return convertRangeToVersList(genericRange);
            } else {
                throw versException;
            }
        }
    }

    private static List<VulnerableSoftware> convertVersToVulnerableSoftware(
            final Vers vers,
            final String vulnId,
            final Component affectedComponent) {
        String versionStartIncluding = null;
        String versionStartExcluding = null;
        String versionEndIncluding = null;
        String versionEndExcluding = null;

        for (final Constraint constraint : vers.constraints()) {
            if (constraint.version() == null
                || constraint.version().toString().equals("0")
                || constraint.version().toString().equals("*")) {
                // Semantically, ">=0" is equivalent to versionStartIncluding=null,
                // and ">0" is equivalent to versionStartExcluding=null.
                //
                // "<0", "<=0", and "=0" can be normalized to versionStartIncluding=null.
                //
                // "*" is a wildcard and can only be used on its own, without any comparator.
                // The Vers parsing / validation performed above will thus fail for ranges like "vers:generic/>=*".
                continue;
            }

            switch (constraint.comparator()) {
                case GREATER_THAN -> versionStartExcluding = String.valueOf(constraint.version());
                case GREATER_THAN_OR_EQUAL -> versionStartIncluding = String.valueOf(constraint.version());
                case LESS_THAN_OR_EQUAL -> versionEndIncluding = String.valueOf(constraint.version());
                case LESS_THAN -> versionEndExcluding = String.valueOf(constraint.version());
                default -> LOGGER.warn(
                        "Encountered unexpected comparator %s in %s for %s; Skipping".formatted(
                                constraint.comparator(), vers, vulnId));
            }
        }

        if (versionStartIncluding == null && versionStartExcluding == null
            && versionEndIncluding == null && versionEndExcluding == null) {
            LOGGER.warn("Unable to assemble a version range from %s for %s".formatted(vers, vulnId));
            return Collections.emptyList();
        }
        if ((versionStartIncluding != null || versionStartExcluding != null)
            && (versionEndIncluding == null && versionEndExcluding == null)) {
            LOGGER.warn("Skipping indefinite version range assembled from %s for %s".formatted(vers, vulnId));
            return Collections.emptyList();
        }

        final var vsList = new ArrayList<VulnerableSoftware>(2);
        if (affectedComponent.hasCpe()) {
            try {
                final Cpe cpe = CpeParser.parse(affectedComponent.getCpe());

                final var vs = new VulnerableSoftware();
                vs.setCpe22(cpe.toCpe22Uri());
                vs.setCpe23(affectedComponent.getCpe());
                vs.setPart(cpe.getPart().getAbbreviation());
                vs.setVendor(cpe.getVendor());
                vs.setProduct(cpe.getProduct());
                vs.setVersion(cpe.getVersion());
                vs.setUpdate(cpe.getUpdate());
                vs.setEdition(cpe.getEdition());
                vs.setLanguage(cpe.getLanguage());
                vs.setSwEdition(cpe.getSwEdition());
                vs.setTargetSw(cpe.getTargetSw());
                vs.setTargetHw(cpe.getTargetHw());
                vs.setOther(cpe.getOther());
                vs.setVersionStartExcluding(versionStartExcluding);
                vs.setVersionStartIncluding(versionStartIncluding);
                vs.setVersionEndExcluding(versionEndExcluding);
                vs.setVersionEndIncluding(versionEndIncluding);
                vs.setVulnerable(true);

                vsList.add(vs);
            } catch (CpeParsingException e) {
                LOGGER.warn("Failed to parse CPE %s of %s; Skipping".formatted(
                        affectedComponent.getCpe(), vulnId), e);
            } catch (CpeEncodingException e) {
                LOGGER.warn("Failed to encode CPE %s of %s; Skipping".formatted(
                        affectedComponent.getCpe(), vulnId), e);
            }
        }
        if (affectedComponent.hasPurl()) {
            try {
                final PackageURL purl = new PackageURL(affectedComponent.getPurl());

                final var vs = new VulnerableSoftware();
                vs.setPurlType(purl.getType());
                vs.setPurlNamespace(purl.getNamespace());
                vs.setPurlName(purl.getName());
                vs.setPurl(purl.canonicalize());
                vs.setVersionStartExcluding(versionStartExcluding);
                vs.setVersionStartIncluding(versionStartIncluding);
                vs.setVersionEndExcluding(versionEndExcluding);
                vs.setVersionEndIncluding(versionEndIncluding);
                vs.setVulnerable(true);

                vsList.add(vs);
            } catch (MalformedPackageURLException e) {
                LOGGER.warn(
                        "Failed to parse PURL from \"%s\" for %s; Skipping".formatted(
                                affectedComponent.getPurl(), vulnId), e);
            }
        }

        return vsList;
    }

    public static Predicate<VulnerableSoftware> distinctIgnoringDatastoreIdentity() {
        final var seen = new HashSet<Integer>();
        return vs -> seen.add(vs.hashCodeWithoutDatastoreIdentity());
    }

}
