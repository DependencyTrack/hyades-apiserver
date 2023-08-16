package org.dependencytrack.parser.hyades;

import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.proto.v1_4.Bom;
import org.cyclonedx.proto.v1_4.ScoreMethod;
import org.cyclonedx.proto.v1_4.Source;
import org.cyclonedx.proto.v1_4.VulnerabilityRating;
import org.cyclonedx.proto.v1_4.VulnerabilityReference;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.vulnanalysis.v1.Scanner;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;
import us.springett.owasp.riskrating.MissingFactorException;
import us.springett.owasp.riskrating.OwaspRiskRating;

import java.math.BigDecimal;
import java.sql.Date;
import java.time.Instant;
import java.util.Comparator;

public final class ModelConverterCdxToVuln {

    static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";

    public static Vulnerability convert(final QueryManager qm, final Bom bom,
                                        final org.cyclonedx.proto.v1_4.Vulnerability cycloneVuln,
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
            if (titleProperty != null
                    && titleProperty.getName().equals(TITLE_PROPERTY_NAME)
                    && titleProperty.hasValue()) {
                vuln.setTitle(StringUtils.abbreviate(titleProperty.getValue(), 255));
            }
        }
        vuln.setDescription(cycloneVuln.getDescription());
        vuln.setDetail(cycloneVuln.getDetail());
        vuln.setRecommendation(cycloneVuln.getRecommendation());
        vuln.setPublished(Date.from(Instant.ofEpochSecond(cycloneVuln.getPublished().getSeconds())));
        vuln.setUpdated(Date.from(Instant.ofEpochSecond(cycloneVuln.getUpdated().getSeconds())));
        vuln.setCreated(Date.from(Instant.ofEpochSecond(cycloneVuln.getCreated().getSeconds())));

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


        if (!cycloneVuln.getCwesList().isEmpty()) {
            cycloneVuln.getCwesList().forEach(cweId -> {
                final Cwe cwe = qm.getCweById(cweId);
                if (cwe != null) {
                    vuln.addCwe(cwe);
                }
            });
        }
        cycloneVuln.getRatingsList().stream()
                .sorted(compareRatings(cycloneVuln.getSource()))
                .forEach(rating -> {
                    if (rating.hasMethod()) {
                        final Cvss cvss = Cvss.fromVector(rating.getVector());
                        if (vuln.getCvssV3Vector() == null &&
                                (rating.getMethod().equals(ScoreMethod.SCORE_METHOD_CVSSV3)
                                        || rating.getMethod().equals(ScoreMethod.SCORE_METHOD_CVSSV31))) {
                            vuln.setCvssV3Vector(rating.getVector());
                            vuln.setCvssV3BaseScore(BigDecimal.valueOf(rating.getScore()));
                            if (cvss != null) {
                                final Score score = cvss.calculateScore();
                                vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                                vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                                if (rating.getScore() == 0.0) {
                                    vuln.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                                }
                            }
                        }
                        if (vuln.getCvssV2Vector() == null && rating.getMethod().equals(ScoreMethod.SCORE_METHOD_CVSSV2)) {
                            vuln.setCvssV2Vector(rating.getVector());
                            vuln.setCvssV2BaseScore(BigDecimal.valueOf(rating.getScore()));
                            if (cvss != null) {
                                final Score score = cvss.calculateScore();
                                vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                                vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                                if (rating.getScore() == 0.0) {
                                    vuln.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                                }
                            }
                        }
                        if (vuln.getOwaspRRVector() == null && rating.getMethod().equals(ScoreMethod.SCORE_METHOD_OWASP)) {
                            try {
                                final OwaspRiskRating orr = OwaspRiskRating.fromVector(rating.getVector());
                                final us.springett.owasp.riskrating.Score orrScore = orr.calculateScore();
                                vuln.setOwaspRRVector(rating.getVector());
                                vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(orrScore.getLikelihoodScore()));
                                vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(orrScore.getBusinessImpactScore()));
                                vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(orrScore.getTechnicalImpactScore()));
                            } catch (IllegalArgumentException | MissingFactorException e) {
                                // Ignore
                            }
                        }
                    }
                });

        if (isAliasSyncEnabled && !cycloneVuln.getReferencesList().isEmpty()) {
            vuln.setAliases(cycloneVuln.getReferencesList().stream()
                    .map(alias -> convert(cycloneVuln, alias)).toList());
        }
        return vuln;
    }

    private static VulnerabilityAlias convert(final org.cyclonedx.proto.v1_4.Vulnerability cycloneVuln,
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
            default -> throw new IllegalArgumentException("Invalid source %s for alias %s"
                    .formatted(cycloneAlias.getSource().getName(), cycloneAlias.getId()));
        }
        return alias;
    }


    public static Severity calculateSeverity(Bom bom) {
        if (bom.getVulnerabilitiesCount() > 0
                && bom.getVulnerabilities(0).getRatingsCount() > 0) {
            org.cyclonedx.proto.v1_4.Severity severity =
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
            default -> source != null ? Vulnerability.Source.valueOf(source.getName()) : Vulnerability.Source.INTERNAL;
        };
    }

    public static AnalyzerIdentity convert(final Scanner scanner) {
        return switch (scanner) {
            case SCANNER_INTERNAL -> AnalyzerIdentity.INTERNAL_ANALYZER;
            case SCANNER_OSSINDEX -> AnalyzerIdentity.OSSINDEX_ANALYZER;
            case SCANNER_SNYK -> AnalyzerIdentity.SNYK_ANALYZER;
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
