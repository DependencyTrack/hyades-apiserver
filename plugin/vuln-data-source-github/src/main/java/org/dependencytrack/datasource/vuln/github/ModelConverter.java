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
package org.dependencytrack.datasource.vuln.github;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import com.google.protobuf.util.Timestamps;
import io.github.jeremylong.openvulnerability.client.ghsa.CWEs;
import io.github.jeremylong.openvulnerability.client.ghsa.Identifier;
import io.github.jeremylong.openvulnerability.client.ghsa.Package;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.ExternalReference;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.ScoreMethod;
import org.cyclonedx.proto.v1_6.Severity;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityAffectedVersions;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.cyclonedx.proto.v1_6.VulnerabilityRating;
import org.cyclonedx.proto.v1_6.VulnerabilityReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.cvss.Cvss;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.CvssV3_1;
import us.springett.cvss.MalformedVectorException;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;
import static io.github.nscuro.versatile.VersUtils.versFromGhsaRange;
import static org.cyclonedx.proto.v1_6.Severity.SEVERITY_CRITICAL;
import static org.cyclonedx.proto.v1_6.Severity.SEVERITY_HIGH;
import static org.cyclonedx.proto.v1_6.Severity.SEVERITY_INFO;
import static org.cyclonedx.proto.v1_6.Severity.SEVERITY_LOW;
import static org.cyclonedx.proto.v1_6.Severity.SEVERITY_MEDIUM;
import static org.cyclonedx.proto.v1_6.Severity.SEVERITY_NONE;
import static org.cyclonedx.proto.v1_6.Severity.SEVERITY_UNKNOWN;

/**
 * @since 5.7.0
 */
final class ModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ModelConverter.class);
    private static final Source SOURCE = Source.newBuilder().setName("GITHUB").build();
    private static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";

    private ModelConverter() {
    }

    static Bom convert(final SecurityAdvisory advisory, boolean aliasSyncEnabled) {
        final Vulnerability.Builder vulnBuilder = Vulnerability.newBuilder()
                .setSource(SOURCE)
                .setId(advisory.getGhsaId())
                .setDescription(Optional.ofNullable(advisory.getDescription()).orElse(""))
                .addAllCwes(parseCwes(advisory.getCwes()));

        Optional.ofNullable(advisory.getSummary()).ifPresent(title -> vulnBuilder.addProperties(
                Property.newBuilder().setName(TITLE_PROPERTY_NAME).setValue(abbreviate(title, 255)).build()));

        parseRating(advisory).ifPresent(vulnBuilder::addRatings);

        // Alias is mapped only if aliasSync is enabled
        if (aliasSyncEnabled) {
            Optional.ofNullable(mapVulnerabilityReferences(advisory)).ifPresent(vulnBuilder::addAllReferences);
        }

        Optional.ofNullable(advisory.getPublishedAt())
                .map(ZonedDateTime::toInstant)
                .map(Instant::toEpochMilli)
                .map(Timestamps::fromMillis)
                .ifPresent(vulnBuilder::setPublished);

        Optional.ofNullable(advisory.getUpdatedAt())
                .map(ZonedDateTime::toInstant)
                .map(Instant::toEpochMilli)
                .map(Timestamps::fromMillis)
                .ifPresent(vulnBuilder::setUpdated);

        Optional.ofNullable(advisory.getWithdrawnAt())
                .map(ZonedDateTime::toInstant)
                .map(Instant::toEpochMilli)
                .map(Timestamps::fromMillis)
                .ifPresent(vulnBuilder::setRejected);

        final var componentByPurl = new HashMap<String, Component>();
        final var vulnAffectsBuilderByBomRef = new HashMap<String, VulnerabilityAffects.Builder>();

        if (advisory.getVulnerabilities() != null && advisory.getVulnerabilities().getEdges() != null) {

            for (final io.github.jeremylong.openvulnerability.client.ghsa.Vulnerability gitHubVulnerability : advisory.getVulnerabilities().getEdges()) {
                PackageURL purl = convertToPurl(gitHubVulnerability.getPackage());
                if (purl == null) {
                    //drop mapping if purl is null
                    continue;
                }

                final Component component = componentByPurl.computeIfAbsent(
                        purl.getCoordinates(),
                        purlCoordinates -> Component.newBuilder()
                                .setBomRef(UUID.nameUUIDFromBytes(purlCoordinates.getBytes()).toString())
                                .setPurl(purlCoordinates)
                                .build());

                final VulnerabilityAffects.Builder affectsBuilder = vulnAffectsBuilderByBomRef.computeIfAbsent(
                        component.getBomRef(),
                        bomRef -> VulnerabilityAffects.newBuilder()
                                .setRef(bomRef));

                var parsedVersionRange = parseVersionRangeAffected(gitHubVulnerability);
                if (parsedVersionRange != null) {
                    affectsBuilder.addVersions(parsedVersionRange);
                }
            }
        }

        // Sort components by BOM ref to ensure consistent ordering.
        final List<Component> components = componentByPurl.values().stream()
                .sorted(java.util.Comparator.comparing(Component::getBomRef))
                .toList();

        // Sort affects by BOM ref to ensure consistent ordering.
        final List<VulnerabilityAffects> vulnAffects = vulnAffectsBuilderByBomRef.values().stream()
                .map(VulnerabilityAffects.Builder::build)
                .sorted(java.util.Comparator.comparing(VulnerabilityAffects::getRef))
                .toList();

        final Bom.Builder bomBuilder = Bom.newBuilder()
                .addAllComponents(components)
                .addVulnerabilities(vulnBuilder.addAllAffects(vulnAffects));

        Optional.ofNullable(mapExternalReferences(advisory)).ifPresent(bomBuilder::addAllExternalReferences);

        return bomBuilder.build();
    }

    private static Optional<VulnerabilityRating> parseRating(final SecurityAdvisory advisory) {
        if (advisory.getCvssSeverities() != null
                && advisory.getCvssSeverities().getCvssV3() != null
                && StringUtils.trimToNull(advisory.getCvssSeverities().getCvssV3().getVectorString()) != null) {
            final String cvssVector = StringUtils.trimToNull(advisory.getCvssSeverities().getCvssV3().getVectorString());
            final Cvss cvss;
            try {
                cvss = Cvss.fromVector(cvssVector);
                if (cvss == null) {
                    return Optional.empty();
                }
            } catch (MalformedVectorException e) {
                LOGGER.warn("Failed to parse rating: CVSS vector {} is malformed; Skipping", cvssVector, e);
                return Optional.empty();
            }

            final VulnerabilityRating.Builder cvssRatingBuilder = VulnerabilityRating.newBuilder()
                    .setSource(SOURCE)
                    .setVector(cvss.getVector())
                    .setScore(cvss.calculateScore().getBaseScore())
                    .setSeverity(calculateCvssSeverity(cvss));
            if (cvss instanceof CvssV3_1) {
                return Optional.of(cvssRatingBuilder.setMethod(ScoreMethod.SCORE_METHOD_CVSSV31).build());
            } else if (cvss instanceof CvssV3) {
                return Optional.of(cvssRatingBuilder.setMethod(ScoreMethod.SCORE_METHOD_CVSSV3).build());
            } else if (cvss instanceof CvssV2) {
                return Optional.of(cvssRatingBuilder.setMethod(ScoreMethod.SCORE_METHOD_CVSSV2).build());
            }
        } else if (advisory.getSeverity() != null && StringUtils.trimToNull(advisory.getSeverity().value()) != null) {
            return Optional.of(VulnerabilityRating.newBuilder()
                    .setSource(SOURCE)
                    .setMethod(ScoreMethod.SCORE_METHOD_OTHER)
                    .setSeverity(mapSeverity(StringUtils.trimToNull(advisory.getSeverity().value())))
                    .build());
        }

        return Optional.empty();
    }

    private static List<VulnerabilityReference> mapVulnerabilityReferences(final SecurityAdvisory advisory) {
        if (advisory.getIdentifiers() == null || advisory.getIdentifiers().isEmpty()) {
            return null;
        }

        final var references = new ArrayList<VulnerabilityReference>();
        for (final Identifier identifier : advisory.getIdentifiers()) {
            if (advisory.getGhsaId().equals(identifier.getValue())) {
                // The advisory's ID is usually repeated in the identifiers array.
                // No need to list the vulnerability ID as reference again.
                continue;
            }

            if (!advisory.getId().equals(identifier.getValue())) {
                // TODO: Consider mapping to CNA names instead (https://github.com/DependencyTrack/hyades/issues/1297).
                final String source = switch (identifier.getType()) {
                    case "CVE" -> "NVD";
                    case "GHSA" -> "GITHUB";
                    default -> null;
                };
                if (source == null) {
                    LOGGER.warn("Unknown type {} for identifier {}; Skipping", identifier.getType(), identifier.getValue());
                    continue;
                }

                references.add(VulnerabilityReference.newBuilder()
                        .setId(identifier.getValue())
                        .setSource(Source.newBuilder().setName(source))
                        .build());
            }
        }

        return references;
    }


    private static List<ExternalReference> mapExternalReferences(SecurityAdvisory advisory) {
        if (advisory.getReferences() == null || advisory.getReferences().isEmpty()) {
            return null;
        }
        List<ExternalReference> externalReferences = new ArrayList<>();
        advisory.getReferences().forEach(reference ->
                externalReferences.add(ExternalReference.newBuilder()
                        .setUrl(reference.getUrl())
                        .build())
        );
        return externalReferences;
    }

    private static VulnerabilityAffectedVersions parseVersionRangeAffected(final io.github.jeremylong.openvulnerability.client.ghsa.Vulnerability vuln) {
        var vulnerableVersionRange = vuln.getVulnerableVersionRange();
        try {
            var vers = versFromGhsaRange(vuln.getPackage().getEcosystem(), vulnerableVersionRange);
            var versionRange = VulnerabilityAffectedVersions.newBuilder();
            return versionRange.setRange(String.valueOf(vers)).build();
        } catch (Exception exception) {
            LOGGER.debug("Exception while parsing Github version range {}", vulnerableVersionRange, exception);
        }
        return null;
    }

    private static List<Integer> parseCwes(CWEs weaknesses) {
        List<Integer> cwes = new ArrayList<>();
        if (weaknesses != null && weaknesses.getEdges() != null) {
            weaknesses.getEdges().forEach(weakness -> {
                String cweString = weakness.getCweId();
                if (cweString != null && cweString.startsWith("CWE-")) {
                    cwes.add(Integer.parseInt(cweString.replaceFirst("^CWE-", "")));
                }
            });
        }
        return cwes;
    }

    private static PackageURL convertToPurl(final Package pkg) {
        final String purlType = switch (pkg.getEcosystem().toLowerCase()) {
            case "composer" -> PackageURL.StandardTypes.COMPOSER;
            case "erlang" -> PackageURL.StandardTypes.HEX;
            case "go" -> PackageURL.StandardTypes.GOLANG;
            case "maven" -> PackageURL.StandardTypes.MAVEN;
            case "npm" -> PackageURL.StandardTypes.NPM;
            case "nuget" -> PackageURL.StandardTypes.NUGET;
            case "other" -> PackageURL.StandardTypes.GENERIC;
            case "pip" -> PackageURL.StandardTypes.PYPI;
            case "pub" -> "pub"; // https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pub
            case "rubygems" -> PackageURL.StandardTypes.GEM;
            case "rust" -> PackageURL.StandardTypes.CARGO;
            case "swift" -> "swift"; // https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#swift
            default -> {
                // Not optimal, but still better than ignoring the package entirely.
                LOGGER.warn("Unrecognized ecosystem %s; Assuming PURL type %s for %s".formatted(
                        pkg.getEcosystem(), PackageURL.StandardTypes.GENERIC, pkg));
                yield PackageURL.StandardTypes.GENERIC;
            }
        };

        final PackageURLBuilder purlBuilder = aPackageURL().withType(purlType);
        if (PackageURL.StandardTypes.MAVEN.equals(purlType) && pkg.getName().contains(":")) {
            final String[] nameParts = pkg.getName().split(":", 2);
            purlBuilder
                    .withNamespace(nameParts[0])
                    .withName(nameParts[1]);
        } else if ((PackageURL.StandardTypes.COMPOSER.equals(purlType)
                || PackageURL.StandardTypes.GOLANG.equals(purlType)
                || PackageURL.StandardTypes.NPM.equals(purlType)
                || PackageURL.StandardTypes.GENERIC.equals(purlType))
                && pkg.getName().contains("/")) {
            final String[] nameParts = pkg.getName().split("/");
            final String namespace = String.join("/", Arrays.copyOfRange(nameParts, 0, nameParts.length - 1));
            purlBuilder
                    .withNamespace(namespace)
                    .withName(nameParts[nameParts.length - 1]);
        } else {
            purlBuilder.withName(pkg.getName());
        }

        try {
            return purlBuilder.build();
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to assemble a valid PURL from {}", pkg, e);
            return null;
        }
    }

    private static Severity calculateCvssSeverity(final Cvss cvss) {
        if (cvss == null) {
            return SEVERITY_UNKNOWN;
        }

        final double baseScore = cvss.calculateScore().getBaseScore();
        if (cvss instanceof us.springett.cvss.CvssV3 || cvss instanceof io.github.jeremylong.openvulnerability.client.nvd.CvssV3) {
            if (baseScore >= 9) {
                return SEVERITY_CRITICAL;
            } else if (baseScore >= 7) {
                return SEVERITY_HIGH;
            } else if (baseScore >= 4) {
                return SEVERITY_MEDIUM;
            } else if (baseScore > 0) {
                return SEVERITY_LOW;
            }
        } else if (cvss instanceof CvssV2) {
            if (baseScore >= 7) {
                return SEVERITY_HIGH;
            } else if (baseScore >= 4) {
                return SEVERITY_MEDIUM;
            } else if (baseScore > 0) {
                return SEVERITY_LOW;
            }
        }

        return SEVERITY_UNKNOWN;
    }

    private static Severity mapSeverity(String severity) {
        if (severity == null) {
            return SEVERITY_UNKNOWN;
        }
        return switch (severity) {
            case "CRITICAL" -> SEVERITY_CRITICAL;
            case "HIGH" -> SEVERITY_HIGH;
            case "MEDIUM", "MODERATE" -> SEVERITY_MEDIUM;
            case "LOW" -> SEVERITY_LOW;
            case "INFO" -> SEVERITY_INFO;
            case "NONE" -> SEVERITY_NONE;
            default -> SEVERITY_UNKNOWN;
        };
    }

    private static String abbreviate(final String value, final int maxLength) {
        if (value != null && value.length() > maxLength) {
            return value.substring(0, maxLength - 3) + "...";
        }

        return value;
    }

}
