package org.dependencytrack.parser.hyades;

import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.hyades.proto.vuln.v1.Alias;
import org.hyades.proto.vuln.v1.Rating;
import org.hyades.proto.vuln.v1.Reference;
import org.hyades.proto.vuln.v1.ScoreMethod;
import org.hyades.proto.vuln.v1.Source;
import us.springett.cvss.Cvss;
import us.springett.owasp.riskrating.MissingFactorException;
import us.springett.owasp.riskrating.OwaspRiskRating;

import java.math.BigDecimal;
import java.sql.Date;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_NULL;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_OTHER;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_OWASP;

/**
 * Helper class to convert from the Hyades model (largely defined via Protocol Buffers) to the internal model of the API server.
 */
public final class ModelConverter {

    private ModelConverter() {
    }

    public static Vulnerability convert(final org.hyades.proto.vuln.v1.Vulnerability hyadesVuln) {
        if (hyadesVuln == null) {
            return null;
        }

        var vuln = new Vulnerability();
        vuln.setVulnId(hyadesVuln.getId());
        vuln.setSource(convert(hyadesVuln.getSource()));
        vuln.setTitle(hyadesVuln.getTitle());
        vuln.setDescription(hyadesVuln.getDescription());
        if (hyadesVuln.hasCreated()) {
            vuln.setCreated(Date.from(Instant.ofEpochSecond(hyadesVuln.getCreated().getSeconds())));
        }
        if (hyadesVuln.hasPublished()) {
            vuln.setPublished(Date.from(Instant.ofEpochSecond(hyadesVuln.getPublished().getSeconds())));
        }
        if (hyadesVuln.hasUpdated()) {
            vuln.setUpdated(Date.from(Instant.ofEpochSecond(hyadesVuln.getUpdated().getSeconds())));
        }

        hyadesVuln.getRatingsList().stream()
                .sorted(compareRatings(hyadesVuln.getSource()))
                .forEach(rating -> applyRating(vuln, rating));

        final var cwes = new ArrayList<Integer>();
        for (final Integer cweId : hyadesVuln.getCwesList()) {
            // Only use the CWE if we can find it in our dictionary
            final Cwe cwe = CweResolver.getInstance().lookup(cweId);
            if (cwe != null) {
                cwes.add(cweId);
            }
        }
        if (!cwes.isEmpty()) {
            vuln.setCwes(cwes);
        }

        final String references = convert(hyadesVuln.getReferencesList());
        if (!references.isEmpty()) {
            vuln.setReferences(references);
        }

        final var aliases = new ArrayList<VulnerabilityAlias>();
        for (final Alias hyadesAlias : hyadesVuln.getAliasesList()) {
            aliases.add(convert(hyadesVuln, hyadesAlias));
        }
        if (!aliases.isEmpty()) {
            vuln.setAliases(aliases);
        }

        return vuln;
    }

    private static Vulnerability.Source convert(final Source source) {
        return switch (source) {
            case SOURCE_GITHUB -> Vulnerability.Source.GITHUB;
            case SOURCE_INTERNAL -> Vulnerability.Source.INTERNAL;
            case SOURCE_NVD -> Vulnerability.Source.NVD;
            case SOURCE_OSSINDEX -> Vulnerability.Source.OSSINDEX;
            case SOURCE_OSV -> Vulnerability.Source.OSV;
            case SOURCE_SNYK -> Vulnerability.Source.SNYK;
            case SOURCE_VULNDB -> Vulnerability.Source.VULNDB;
            default -> throw new IllegalArgumentException("Invalid vulnerability source %s".formatted(source));
        };
    }

    private static VulnerabilityAlias convert(final org.hyades.proto.vuln.v1.Vulnerability hyadesVuln, final Alias hyadesAlias) {
        final var alias = new VulnerabilityAlias();

        switch (hyadesVuln.getSource()) {
            case SOURCE_GITHUB -> alias.setGhsaId(hyadesVuln.getId());
            case SOURCE_INTERNAL -> alias.setInternalId(hyadesVuln.getId());
            case SOURCE_NVD -> alias.setCveId(hyadesVuln.getId());
            case SOURCE_OSSINDEX -> alias.setSonatypeId(hyadesVuln.getId());
            case SOURCE_OSV -> alias.setOsvId(hyadesVuln.getId());
            case SOURCE_SNYK -> alias.setSnykId(hyadesVuln.getId());
            case SOURCE_VULNDB -> alias.setVulnDbId(hyadesVuln.getId());
            // Source of the vulnerability itself has been validated before,
            // so this scenario is highly unlikely to ever happen. Including
            // it here to make linters happy.
            default ->
                    throw new IllegalArgumentException("Invalid vulnerability source %s".formatted(hyadesVuln.getSource()));
        }

        switch (hyadesAlias.getSource()) {
            case SOURCE_GITHUB -> alias.setGhsaId(hyadesAlias.getId());
            case SOURCE_INTERNAL -> alias.setInternalId(hyadesAlias.getId());
            case SOURCE_NVD -> alias.setCveId(hyadesAlias.getId());
            case SOURCE_OSSINDEX -> alias.setSonatypeId(hyadesAlias.getId());
            case SOURCE_OSV -> alias.setOsvId(hyadesAlias.getId());
            case SOURCE_SNYK -> alias.setSnykId(hyadesAlias.getId());
            case SOURCE_VULNDB -> alias.setVulnDbId(hyadesAlias.getId());
            default -> throw new IllegalArgumentException("Invalid source %s for alias %s"
                    .formatted(hyadesAlias.getSource(), hyadesAlias.getId()));
        }

        return alias;
    }

    private static final List<ScoreMethod> SCORE_METHOD_PRIORITY = List.of(
            SCORE_METHOD_CVSSV31,
            SCORE_METHOD_CVSSV3,
            SCORE_METHOD_CVSSV2,
            SCORE_METHOD_OWASP,
            SCORE_METHOD_OTHER,
            SCORE_METHOD_NULL,
            ScoreMethod.UNRECOGNIZED
    );

    /**
     * Vulnerabilities can have multiple risk ratings of the same type, but DT currently only supports one.
     *
     * @param vulnSource (Authoritative) {@link Source} of the vulnerability
     * @return A {@link Consumer} that sets the selected {@link Rating}
     */
    private static Comparator<Rating> compareRatings(final Source vulnSource) {
        return (left, right) -> {
            // Prefer ratings from the vulnerability's authoritative source.
            if (left.getSource() == vulnSource && right.getSource() != vulnSource) {
                return -1;
            } else if (left.getSource() != vulnSource && right.getSource() == vulnSource) {
                return 1;
            }

            // Prefer specified method over no / unknown methods.
            if (left.hasMethod() && !right.hasMethod()) {
                return -1;
            } else if (!left.hasMethod() && right.hasMethod()) {
                return 1;
            }

            return Integer.compare(
                    SCORE_METHOD_PRIORITY.indexOf(left.getMethod()),
                    SCORE_METHOD_PRIORITY.indexOf(right.getMethod())
            );
        };
    }

    private static void applyRating(final Vulnerability vuln, final Rating rating) {
        if (vuln.getCvssV3Vector() == null
                && (rating.getMethod() == SCORE_METHOD_CVSSV31 || rating.getMethod() == SCORE_METHOD_CVSSV3)) {
            final Cvss cvss = Cvss.fromVector(rating.getVector());
            if (cvss != null) {
                final us.springett.cvss.Score score = cvss.calculateScore();
                vuln.setCvssV3Vector(cvss.getVector());
                vuln.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            }
        } else if (vuln.getCvssV2Vector() == null && rating.getMethod() == SCORE_METHOD_CVSSV2) {
            final Cvss cvss = Cvss.fromVector(rating.getVector());
            if (cvss != null) {
                final us.springett.cvss.Score score = cvss.calculateScore();
                vuln.setCvssV2Vector(cvss.getVector());
                vuln.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            }
        } else if (vuln.getOwaspRRVector() == null && rating.getMethod() == SCORE_METHOD_OWASP) {
            try {
                final OwaspRiskRating orr = OwaspRiskRating.fromVector(rating.getVector());
                final us.springett.owasp.riskrating.Score orrScore = orr.calculateScore();
                vuln.setOwaspRRVector(rating.getVector());
                vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(orrScore.getLikelihoodScore()));
                vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(orrScore.getBusinessImpactScore()));
                vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(orrScore.getTechnicalImpactScore()));
            } catch (MissingFactorException e) {
                // Ignore
            }
        }
    }

    private static String convert(final List<Reference> references) {
        return references.stream()
                .map(reference -> {
                    if (reference.hasDisplayName()) {
                        return "* [%s](%s)".formatted(reference.getDisplayName(), reference.getUrl());
                    } else {
                        return "* [%s](%s)".formatted(reference.getUrl(), reference.getUrl());
                    }
                })
                .collect(Collectors.joining("\n"));
    }

}
