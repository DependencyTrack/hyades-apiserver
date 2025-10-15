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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.google.protobuf.Timestamp;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.proto.v1_6.Advisory;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.ExternalReference;
import org.cyclonedx.proto.v1_6.OrganizationalContact;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.ScoreMethod;
import org.cyclonedx.proto.v1_6.Severity;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityAffectedVersions;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.cyclonedx.proto.v1_6.VulnerabilityCredits;
import org.cyclonedx.proto.v1_6.VulnerabilityRating;
import org.cyclonedx.proto.v1_6.VulnerabilityReference;
import org.dependencytrack.datasource.vuln.osv.schema.Affected;
import org.dependencytrack.datasource.vuln.osv.schema.Credit;
import org.dependencytrack.datasource.vuln.osv.schema.DatabaseSpecific__1;
import org.dependencytrack.datasource.vuln.osv.schema.EcosystemSpecific;
import org.dependencytrack.datasource.vuln.osv.schema.Event;
import org.dependencytrack.datasource.vuln.osv.schema.OsvSchema;
import org.dependencytrack.datasource.vuln.osv.schema.Package;
import org.dependencytrack.datasource.vuln.osv.schema.Range;
import org.dependencytrack.datasource.vuln.osv.schema.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.cvss.Cvss;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.CvssV3_1;
import us.springett.cvss.MalformedVectorException;
import us.springett.cvss.Score;

import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.github.nscuro.versatile.VersUtils.versFromOsvRange;
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
    private static final Pattern WILDCARD_VERS_PATTERN = Pattern.compile("^vers:\\w+/\\*$");
    private static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    static Bom convert(final OsvSchema schemaInput, final boolean isAliasSyncEnabled, final String currentEcosystem) {
        if (schemaInput.getWithdrawn() != null) {
            return null;
        }
        Bom.Builder cyclonedxBom = Bom.newBuilder();
        return cyclonedxBom
                .addVulnerabilities(extractVulnerability(schemaInput, isAliasSyncEnabled, cyclonedxBom, currentEcosystem))
                .build();
    }

    private static Vulnerability extractVulnerability(final OsvSchema schemaInput, final boolean isAliasSyncEnabled, Bom.Builder cyclonedxBom, final String currentEcosystem) {
        Vulnerability.Builder vulnerability = Vulnerability.newBuilder();
        var severity = SEVERITY_UNKNOWN;

        Optional.ofNullable(schemaInput.getId()).ifPresent(vulnerability::setId);
        vulnerability.setSource(extractSource(schemaInput.getId()));
        vulnerability.addProperties(Property.newBuilder()
                .setName(CycloneDxPropertyNames.PROPERTY_OSV_ECOSYSTEM)
                .setValue(currentEcosystem));
        Optional.ofNullable(schemaInput.getSummary()).ifPresent(summary -> vulnerability.addProperties(
                Property.newBuilder().setName(TITLE_PROPERTY_NAME).setValue(trimSummary(summary)).build()));
        Optional.ofNullable(schemaInput.getDetails()).ifPresent(vulnerability::setDescription);

        Optional.ofNullable(schemaInput.getPublished())
                .map(Date::toInstant)
                .map(instant -> Timestamp.newBuilder().setSeconds(instant.getEpochSecond()))
                .ifPresent(vulnerability::setPublished);

        Optional.ofNullable(schemaInput.getModified())
                .map(Date::toInstant)
                .map(instant -> Timestamp.newBuilder().setSeconds(instant.getEpochSecond()))
                .ifPresent(vulnerability::setUpdated);

        if (schemaInput.getDatabaseSpecific() != null) {
            if (schemaInput.getDatabaseSpecific().getAdditionalProperties().containsKey("cwe_ids")) {
                @SuppressWarnings("unchecked")
                List<String> cwes = (List<String>) schemaInput.getDatabaseSpecific()
                        .getAdditionalProperties()
                        .get("cwe_ids");
                vulnerability.addAllCwes(getCweIds(cwes));
            }
            if (schemaInput.getDatabaseSpecific().getAdditionalProperties().containsKey("severity")) {
                //this severity is compared with affected package severities and highest set
                String severityObj = (String) schemaInput.getDatabaseSpecific().getAdditionalProperties().get("severity");
                severity = mapSeverity(severityObj);
            }
        }

        if (isAliasSyncEnabled) {
            vulnerability.addAllReferences(mapAliases(schemaInput.getAliases()));
        }

        Optional.ofNullable(mapCredits(schemaInput.getCredits())).ifPresent(vulnerability::setCredits);
        Optional.ofNullable(mapReferences(schemaInput.getReferences()).get("ADVISORY")).ifPresent(vulnerability::addAllAdvisories);
        Optional.ofNullable(mapReferences(schemaInput.getReferences()).get("EXTERNAL")).ifPresent(cyclonedxBom::addAllExternalReferences);

        //affected ranges
        List<Affected> osvAffectedArray = schemaInput.getAffected();
        if (osvAffectedArray != null) {
            // affected packages and versions
            // low-priority severity assignment
            vulnerability.addAllAffects(parseAffectedRanges(vulnerability.getId(), osvAffectedArray, cyclonedxBom));
            severity = parseSeverity(osvAffectedArray);
        }

        // CVSS ratings
        vulnerability.addAllRatings(parseCvssRatings(schemaInput, severity));

        return vulnerability.build();
    }

    static String trimSummary(String summary) {
        int MAX_LEN = 255;
        if (summary != null && summary.length() > 255) {
            return StringUtils.substring(summary, 0, MAX_LEN - 2) + "..";
        }
        return summary;
    }

    private static Source extractSource(String vulnId) {
        final String sourceId = vulnId.split("-")[0];
        var source = Source.newBuilder();
        return switch (sourceId) {
            case "GHSA" -> source.setName("GITHUB").build();
            case "CVE" -> source.setName("NVD").build();
            default -> source.setName("OSV").build();
        };
    }

    private static List<Integer> getCweIds(final List<String> cwes) {
        List<Integer> cweIds = new ArrayList<>();
        if(cwes == null) {
            return cweIds;
        }
        cwes.forEach(cwe -> cweIds.add(parseCweString(cwe)));
        return cweIds;
    }

    private static Integer parseCweString(final String cweString) {
        if (StringUtils.isNotBlank(cweString)) {
            final String string = cweString.trim();
            String lookupString = "";
            if (string.startsWith("CWE-") && string.contains(" ")) {
                // This is likely to be in the following format:
                // CWE-264 Permissions, Privileges, and Access Controls
                lookupString = string.substring(4, string.indexOf(" "));
            } else if (string.startsWith("CWE-") && string.length() < 9) {
                // This is likely to be in the following format:
                // CWE-264
                lookupString = string.substring(4);
            } else if (string.length() < 5) {
                // This is likely to be in the following format:
                // 264
                lookupString = string;
            }
            try {
                return Integer.valueOf(lookupString);
            } catch (NumberFormatException e) {
                // throw it away
            }
        }
        return null;
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

    private static List<VulnerabilityReference> mapAliases(List<String> aliases) {
        List<VulnerabilityReference> aliasReferences = new ArrayList<>();
        if (aliases == null) {
            return aliasReferences;
        }
        aliases.stream().forEach(alias -> {
            var reference = VulnerabilityReference.newBuilder()
                    .setId(alias)
                    .setSource(Source.newBuilder()
                            .setName(extractSource(alias).getName())
                            .build())
                    .build();
            aliasReferences.add(reference);
        });
        return aliasReferences;
    }

    private static VulnerabilityCredits mapCredits(List<Credit> credits) {
        if (credits == null || credits.isEmpty()) {
            return null;
        }
        var vulnerabilityCredits = VulnerabilityCredits.newBuilder();
        List<OrganizationalContact> creditArray = new ArrayList<>();
        credits.forEach(credit -> {
            var orgContact = OrganizationalContact.newBuilder();
            orgContact.setName(credit.getName());
            if (credit.getContact() != null) {
                String contactLink = String.join(";", credit.getContact());
                if (!contactLink.isEmpty()) {
                    orgContact.setEmail(contactLink);
                }
            }
            creditArray.add(orgContact.build());
        });
        vulnerabilityCredits.addAllIndividuals(creditArray);
        return vulnerabilityCredits.build();
    }

    private static Map<String, List> mapReferences(List<Reference> references) {
        if (references == null) {
            return Collections.emptyMap();
        }
        List<ExternalReference> externalReferences = new ArrayList<>();
        List<Advisory> advisories = new ArrayList<>();

        references.forEach(reference -> {
            String url = reference.getUrl();
            if (reference.getType() != null && reference.getType().value().equalsIgnoreCase("ADVISORY")) {
                var advisory = Advisory.newBuilder()
                        .setUrl(url).build();
                advisories.add(advisory);
            } else {
                var externalReference = ExternalReference.newBuilder().setUrl(url).build();
                externalReferences.add(externalReference);
            }
        });
        return Map.of("ADVISORY", advisories, "EXTERNAL", externalReferences);
    }

    private static List<VulnerabilityAffects> parseAffectedRanges(final String vulnId, List<Affected> osvAffectedArray, Bom.Builder bom) {
        List<VulnerabilityAffects> affects = new ArrayList<>();

        for (Affected osvAffectedObj : osvAffectedArray) {
            Package packageObj = osvAffectedObj.getPackage();
            String purl = packageObj.getPurl();
            if (purl == null) {
                LOGGER.debug("affected node for vulnerability {} does not provide a PURL; Skipping", vulnId);
                continue;
            }
            try {
                new PackageURL(purl);
            } catch (MalformedPackageURLException ex) {
                LOGGER.warn("Failed to parse PURL \"{}\" from affected node for vulnerability {}", purl, vulnId, ex);
                continue;
            }
            String bomReference = getBomRefIfComponentExists(bom.build(), purl);
            if (bomReference == null) {
                Component component = createNewComponentWithPurl(packageObj, purl);
                bom.addComponents(component);
                bomReference = component.getBomRef();
            }
            VulnerabilityAffects versionRangeAffected = getAffectedPackageVersionRange(osvAffectedObj);
            VulnerabilityAffects rangeWithBomReference = VulnerabilityAffects.newBuilder(versionRangeAffected)
                    .setRef(bomReference).build();
            affects.add(rangeWithBomReference);
        }
        return affects;
    }

    public static String getBomRefIfComponentExists(Bom cyclonedxBom, String purl) {
        if (purl != null) {
            Optional<Component> existingComponent = cyclonedxBom.getComponentsList().stream().filter(c ->
                    c.getPurl().equalsIgnoreCase(purl)).findFirst();
            if (existingComponent.isPresent()) {
                return existingComponent.get().getBomRef();
            }
        }
        return null;
    }

    private static Component createNewComponentWithPurl(Package packageObj, String purl) {
        UUID uuid = UUID.nameUUIDFromBytes((purl).getBytes(StandardCharsets.UTF_8));
        Component.Builder component = Component.newBuilder().setBomRef(uuid.toString());
        Optional.ofNullable(packageObj.getName()).ifPresent(component::setName);
        Optional.ofNullable(purl).ifPresent(component::setPurl);
        return component.build();
    }

    private static VulnerabilityAffects getAffectedPackageVersionRange(Affected osvAffectedObj) {
        // Ranges and Versions for each affected package
        final List<Range> rangesArr = osvAffectedObj.getRanges();
        final List<String> versions = osvAffectedObj.getVersions();
        final DatabaseSpecific__1 databaseSpecific = osvAffectedObj.getDatabaseSpecific();

        var versionRangeAffected = VulnerabilityAffects.newBuilder();
        List<VulnerabilityAffectedVersions> versionRanges = new ArrayList<>();

        if (rangesArr != null) {
            rangesArr.forEach(item -> {
                versionRanges.addAll(
                        generateRangeSpecifier(item,
                                osvAffectedObj.getPackage().getEcosystem(),
                                databaseSpecific));
            });
        }

        // OSV expands ranges into exact versions. While this is a nice service to offer, it means
        // that we'll get duplicate data if we consume both the ranges and exact versions.
        //
        // On the other hand, there are cases like https://osv-vulnerabilities.storage.googleapis.com/npm/MAL-2023-995.json,
        // where the range is expressing a `>=0` constraint, but an exact version (`103.99.99`) is provided.
        // Consuming only the range, or both range and exact version will yield false positives.
        //
        // Thus, we only consume exact versions when either:
        //   * No ranges could be parsed at all
        //   * Only wildcard ranges (`>=0`) were parsed
        // In the latter case, wildcard ranges will be dropped in favor of the exact versions.
        final boolean hasOnlyWildcardRanges = versionRanges.stream()
                .map(VulnerabilityAffectedVersions::getRange)
                .allMatch(WILDCARD_VERS_PATTERN.asPredicate());
        if ((versionRanges.isEmpty() || hasOnlyWildcardRanges) && versions != null) {
            versionRanges.clear(); // Remove any existing wildcard ranges.

            versions.forEach(version -> {
                var versionRange = VulnerabilityAffectedVersions.newBuilder();
                versionRange.setVersion(String.valueOf(version));
                versionRanges.add(versionRange.build());
            });
        }
        versionRangeAffected.addAllVersions(versionRanges);
        return versionRangeAffected.build();
    }

    private static List<VulnerabilityAffectedVersions> generateRangeSpecifier(Range range, String ecoSystem, DatabaseSpecific__1 databaseSpecific) {
        final List<Event> rangeEvents = range.getEvents();

        if (rangeEvents == null) {
            return List.of();
        }
        TypeReference<Map.Entry<String, String>> typeRef = new TypeReference<>() {
        };

        List<Map.Entry<String, String>> rangeEventList = rangeEvents.stream()
                .map(rangeEvent -> objectMapper.convertValue(rangeEvent, typeRef))
                .collect(Collectors.toList());

        final var versionRanges = new ArrayList<VulnerabilityAffectedVersions>();
        String rangeType = range.getType().value();

        try {
            var isLastRangeUpperbound = List.of("fixed", "limit", "last_affected").contains(rangeEventList.getLast().getKey());
            var vers = versFromOsvRange(rangeType, ecoSystem, rangeEventList, isLastRangeUpperbound ? null : databaseSpecific.getAdditionalProperties());
            versionRanges.add(VulnerabilityAffectedVersions.newBuilder().setRange(String.valueOf(vers)).build());
            return versionRanges;
        } catch (Exception exception) {
            LOGGER.debug("Exception while parsing OSV version range.", exception);
        }
        return List.of();
    }

    private static Severity parseSeverity(List<Affected> osvAffectedArray) {
        List<Severity> severities = new ArrayList<>();
        osvAffectedArray.forEach(osvAffected -> {
            final EcosystemSpecific ecosystemSpecific = osvAffected.getEcosystemSpecific();
            final DatabaseSpecific__1 databaseSpecific = osvAffected.getDatabaseSpecific();
            severities.add(
                    parseAffectedPackageSeverity(ecosystemSpecific, databaseSpecific));
        });
        // sort in reverse order (highest severity first)
        return severities.stream()
                .max(Comparator.comparingInt(Severity::getNumber))
                .orElse(Severity.SEVERITY_UNKNOWN);
    }

    private static Severity parseAffectedPackageSeverity(EcosystemSpecific ecosystemSpecific, DatabaseSpecific__1 databaseSpecific) {

        String severity = null;
        if (databaseSpecific != null) {
            if (databaseSpecific.getAdditionalProperties().containsKey("cvss")) {
                String cvssVector = (String) databaseSpecific.getAdditionalProperties().get("cvss");
                try {
                    Cvss cvss = Cvss.fromVector(cvssVector);
                    if (cvss != null) {
                        Score score = cvss.calculateScore();
                        severity = String.valueOf(normalizedCvssV3Score(score.getBaseScore()));
                    }
                } catch (MalformedVectorException e) {
                    LOGGER.warn("Failed to parse severity: CVSS vector {} is malformed; Skipping", cvssVector, e);
                }
            }
        }
        if (severity == null && ecosystemSpecific != null) {
            if (ecosystemSpecific.getAdditionalProperties().containsKey("severity")) {
                severity = (String) ecosystemSpecific.getAdditionalProperties().get("severity");
            }

        }
        return mapSeverity(severity);
    }

    /**
     * Returns the severity based on the numerical CVSS score.
     * @return the severity of the vulnerability
     * @since 3.1.0
     */
    public static Severity normalizedCvssV3Score(final double score) {
        if (score >= 9) {
            return SEVERITY_CRITICAL;
        } else if (score >= 7) {
            return SEVERITY_HIGH;
        } else if (score >= 4) {
            return SEVERITY_MEDIUM;
        } else if (score > 0) {
            return SEVERITY_LOW;
        } else {
            return SEVERITY_UNKNOWN;
        }
    }

    public static Severity normalizedCvssV2Score(final double score) {
        if (score >= 7) {
            return SEVERITY_HIGH;
        } else if (score >= 4) {
            return SEVERITY_MEDIUM;
        } else if (score > 0) {
            return SEVERITY_LOW;
        } else {
            return SEVERITY_UNKNOWN;
        }
    }

    private static List<VulnerabilityRating> parseCvssRatings(OsvSchema osvSchema, Severity severity) {
        List<VulnerabilityRating> ratings = new ArrayList<>();
        final List<org.dependencytrack.datasource.vuln.osv.schema.Severity> cvssList = osvSchema.getSeverity();

        if (cvssList == null || cvssList.isEmpty()) {
            var rating = VulnerabilityRating.newBuilder()
                    .setSeverity(severity).build();
            ratings.add(rating);
            return ratings;
        }
        cvssList.forEach(cvssItem -> {
            String vector = cvssItem.getScore();
            if (vector == null) {
                return;
            }

            final Cvss cvss;
            try {
                cvss = Cvss.fromVector(vector);
            } catch (MalformedVectorException e) {
                LOGGER.warn("Failed to parse CVSS vector: {}", vector, e);
                return;
            }

            double score = cvss.calculateScore().getBaseScore();

            var rating = VulnerabilityRating.newBuilder();

            rating.setVector(vector);
            rating.setScore(Double.parseDouble(NumberFormat.getInstance(Locale.US).format(score)));

            switch (cvss) {
                case CvssV3_1 ignored -> {
                    rating.setMethod(ScoreMethod.SCORE_METHOD_CVSSV31);
                    rating.setSeverity(normalizedCvssV3Score(score));
                }
                case CvssV3 ignored -> {
                    rating.setMethod(ScoreMethod.SCORE_METHOD_CVSSV3);
                    rating.setSeverity(normalizedCvssV3Score(score));
                }
                case CvssV2 ignored -> {
                    rating.setMethod(ScoreMethod.SCORE_METHOD_CVSSV2);
                    rating.setSeverity(normalizedCvssV2Score(score));
                }
                default -> {
                    rating.setMethod(ScoreMethod.SCORE_METHOD_OTHER);
                    rating.setSeverity(SEVERITY_UNKNOWN);
                }
            }

            ratings.add(rating.build());
        });
        return ratings;
    }
}
