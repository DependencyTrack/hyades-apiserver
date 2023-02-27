package org.dependencytrack.parser.hyades;

import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.hyades.proto.vuln.v1.Alias;
import org.hyades.proto.vuln.v1.Rating;
import org.hyades.proto.vuln.v1.Reference;
import org.hyades.proto.vuln.v1.ScoreMethod;

import java.math.BigDecimal;
import java.sql.Date;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

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

        final var vuln = new Vulnerability();
        vuln.setVulnId(hyadesVuln.getId());
        vuln.setSource(switch (hyadesVuln.getSource()) {
            case SOURCE_GITHUB -> Vulnerability.Source.GITHUB;
            case SOURCE_INTERNAL -> Vulnerability.Source.INTERNAL;
            case SOURCE_NVD -> Vulnerability.Source.NVD;
            case SOURCE_OSSINDEX -> Vulnerability.Source.OSSINDEX;
            case SOURCE_OSV -> Vulnerability.Source.OSV;
            case SOURCE_SNYK -> Vulnerability.Source.SNYK;
            case SOURCE_VULNDB -> Vulnerability.Source.VULNDB;
            default ->
                    throw new IllegalArgumentException("Invalid vulnerability source %s".formatted(hyadesVuln.getSource()));
        });
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

        // Vulnerabilities can have multiple risk ratings of the same type, but DT currently only supports one.
        // For now, we simply use the first one per type. We also only consider ratings from the authoritative
        // source of the vulnerability. Third-party ratings are ignored for now.
        for (final Rating rating : hyadesVuln.getRatingsList()) {
            if (rating.getSource() == hyadesVuln.getSource()) {
                if (rating.getMethod() == ScoreMethod.SCORE_METHOD_CVSSV31 && vuln.getCvssV3Vector() == null) {
                    vuln.setCvssV3Vector(rating.getVector());
                    vuln.setCvssV3BaseScore(BigDecimal.valueOf(rating.getScore()));
                } else if (rating.getMethod() == ScoreMethod.SCORE_METHOD_CVSSV3 && vuln.getCvssV3Vector() == null) {
                    vuln.setCvssV3Vector(rating.getVector());
                    vuln.setCvssV3BaseScore(BigDecimal.valueOf(rating.getScore()));
                } else if (rating.getMethod() == ScoreMethod.SCORE_METHOD_CVSSV2 && vuln.getCvssV2Vector() == null) {
                    vuln.setCvssV2Vector(rating.getVector());
                    vuln.setCvssV2BaseScore(BigDecimal.valueOf(rating.getScore()));
                } else if (rating.getMethod() == ScoreMethod.SCORE_METHOD_OWASP && vuln.getOwaspRRVector() == null) {
                    vuln.setOwaspRRVector(rating.getVector());
                }
            }
        }

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
