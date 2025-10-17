package org.dependencytrack.datasource.vuln.csaf;

import com.google.protobuf.Timestamp;
import io.csaf.retrieval.ResultCompat;
import io.csaf.retrieval.RetrievedDocument;
import io.csaf.schema.generated.Csaf;
import kotlinx.serialization.json.Json;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.OrganizationalContact;
import org.cyclonedx.proto.v1_6.OrganizationalEntity;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.ScoreMethod;
import org.cyclonedx.proto.v1_6.Severity;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityCredits;
import org.cyclonedx.proto.v1_6.VulnerabilityRating;
import org.cyclonedx.proto.v1_6.VulnerabilityReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.cvss.Cvss;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.MalformedVectorException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.cyclonedx.proto.v1_6.Severity.*;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.*;

/**
 * This class takes care of converting a CSAF document to a CycloneDX BOM.
 *
 * @since 5.7.0
 */
final class ModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ModelConverter.class);

    private static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";
    private static final String SOURCE = "CSAF";

    /**
     * Converts a ResultCompat-wrapped {@link RetrievedDocument} to a CycloneDX BOM.
     *
     * @param result the result containing the RetrievedDocument
     * @param currentProvider the current CSAF source provider
     * @return the converted CycloneDX BOM, or null if the result is a failure
     */
    static Bom convert(final ResultCompat<RetrievedDocument> result, final CsafSource currentProvider) {
        if (result.isFailure()) {
            return null;
        }

        final RetrievedDocument retrievedDocument = result.getOrNull();
        assert retrievedDocument != null;
        final Csaf csaf = retrievedDocument.getJson();
        final Csaf.Document csafDoc = csaf.getDocument();
        final Bom.Builder bomBuilder = Bom.newBuilder();

        LOGGER.info("Processing CSAF document {} from provider {}", csaf.getDocument().getTracking().getId(), currentProvider.getUrl());

        var raw = Json.Default.encodeToString(Csaf.Companion.serializer(), csaf);
        bomBuilder
        .addProperties(
                Property.newBuilder()
                        .setName(PROPERTY_ADVISORY_JSON)
                        .setValue(raw)
                        .build())
        .addProperties(
                Property.newBuilder()
                        .setName(PROPERTY_ADVISORY_PROVIDER_ID)
                        .setValue(Integer.toString(currentProvider.getId()))
                        .build())
        .addProperties(Property.newBuilder()
                .setName(PROPERTY_ADVISORY_PUBLISHER_NAMESPACE)
                .setValue(csafDoc
                        .getPublisher()
                        .getNamespace()
                        .toString())
                .build())
        .addProperties(
                Property.newBuilder()
                        .setName(PROPERTY_ADVISORY_TITLE)
                        .setValue(csafDoc.getTitle())
                        .build())
        .addProperties(
                Property.newBuilder()
                        .setName(PROPERTY_ADVISORY_UPDATED)
                        .setValue(csafDoc.getTracking().getCurrent_release_date().toString())
                        .build())
        .addProperties(Property.newBuilder()
                .setName(PROPERTY_ADVISORY_NAME)
                .setValue(csafDoc
                        .getTracking()
                        .getId())
                .build())
        .addProperties(Property.newBuilder()
                .setName(PROPERTY_ADVISORY_VERSION)
                .setValue(csafDoc
                        .getTracking()
                        .getVersion())
                .build())
        .addProperties(Property.newBuilder()
                .setName(PROPERTY_ADVISORY_URL)
                .setValue(retrievedDocument.getUrl())
                .build())
        .addProperties(Property.newBuilder()
                .setName(PROPERTY_ADVISORY_FORMAT)
                .setValue(SOURCE)
                .build()
        );

        List<Csaf.Vulnerability> vulnerabilities = csaf.getVulnerabilities();
        for (int i = 0, vulnerabilitiesSize = vulnerabilities != null ? vulnerabilities.size() : 0; i < vulnerabilitiesSize; i++) {
            Csaf.Vulnerability csafVuln = vulnerabilities.get(i);
            try {
                bomBuilder.addVulnerabilities(extractVulnerability(csafVuln, csafDoc, i));
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("Failed to compute ID for vulnerability in document from provider {} published at {}; Skipping",
                        currentProvider.getName(),
                        retrievedDocument.component2(),
                        e);
            }
        }

        return bomBuilder.build();
    }

    private static Vulnerability.Builder extractVulnerability(Csaf.Vulnerability csafVuln, Csaf.Document csafDoc, int vulnIndex) throws NoSuchAlgorithmException {
        final Vulnerability.Builder out = Vulnerability.newBuilder();
        final var id = computeVulnerabilityId(csafVuln, csafDoc, vulnIndex);

        // Set ID and source
        out.setId(id);
        out.setSource(Source.newBuilder().setName(SOURCE).build());

        LOGGER.info("Processing vulnerability {}{}", id, csafVuln.getTitle() != null ? " (" + csafVuln.getTitle() + ")" : "");

        // Set some custom properties, we can use these to filter vulnerabilities later
        Optional.ofNullable(csafVuln.getTitle())
                .ifPresent(title -> {
                    out.addProperties(
                            Property.newBuilder().setName(TITLE_PROPERTY_NAME).setValue(csafVuln.getTitle()).build()
                    );
                });

        // Set details. We will use the first note with category "description" as the description.
        // All other notes will be added to the details.
        if (csafVuln.getNotes() != null) {
            var details = new StringBuilder();
            for (Csaf.Note note : csafVuln.getNotes()) {
                if (note.getCategory() == Csaf.Category.description) {
                    out.setDescription(note.getText());
                } else {
                    if (note.getTitle() != null) {
                        details.append("##### ").append(note.getTitle()).append("\n\n");
                    }
                    details.append(note.getText()).append("\n");
                }
            }
            if (!details.isEmpty()) {
                out.setDetail(details.toString());
            }
        }

        // Set the published and created timestamps
        Optional.ofNullable(csafVuln.getRelease_date())
                .map(published -> Timestamp.newBuilder().setSeconds(published.getEpochSeconds()).build())
                .ifPresent(out::setPublished);
        Optional.ofNullable(csafVuln.getDiscovery_date())
                .map(created -> Timestamp.newBuilder().setSeconds(created.getEpochSeconds()).build())
                .ifPresent(out::setCreated);

        // Set references to CVE entries
        Optional.ofNullable(csafVuln.getCve())
                .ifPresent(cve -> {
                    out.addReferences(VulnerabilityReference.newBuilder()
                            .setId(cve)
                            .setSource(Source.newBuilder().setName("NVD")
                                    .build()));
                });

        // Set vulnerability scores (CVSS values)
        if (csafVuln.getScores() != null) {
            for (Csaf.Score score : csafVuln.getScores()) {
                Optional.ofNullable(score.getCvss_v2())
                        .flatMap(cvssV2 -> parseCvssVector(cvssV2.getVectorString(), ScoreMethod.SCORE_METHOD_CVSSV2))
                        .ifPresent(out::addRatings);

                Optional.ofNullable(score.getCvss_v3())
                        .flatMap(cvssV2 -> parseCvssVector(cvssV2.getVectorString(), ScoreMethod.SCORE_METHOD_CVSSV3))
                        .ifPresent(out::addRatings);
            }
        }

        // Set credits / acknowledgments
        var builder = VulnerabilityCredits.newBuilder();
        Optional.ofNullable(csafVuln.getAcknowledgments()).ifPresent(acks -> acks.forEach(ack -> {
            if(ack.getOrganization() != null) {
                builder.addOrganizations(OrganizationalEntity.newBuilder()
                        .setName(ack.getOrganization()).build());
            }

            if(ack.getNames() != null) {
                ack.getNames().forEach(name -> {
                    builder.addIndividuals(OrganizationalContact.newBuilder()
                            .setName(name).build());
                });
            }
        }));
        out.setCredits(builder.build());

        // Set CWE by splitting "CWE-" from CWE ID string
        Optional.ofNullable(csafVuln.getCwe())
                .map(cwe -> Integer.parseInt(cwe.getId().split("-")[1]))
                .ifPresent(out::addCwes);
        return out;
    }

    public static Optional<VulnerabilityRating> parseCvssVector(String vector, ScoreMethod method) {
        final Cvss cvss;
        try {
            cvss = Cvss.fromVector(vector);
            if (cvss == null) {
                return Optional.empty();
            }
        } catch (MalformedVectorException e) {
            LOGGER.warn("Failed to parse rating: CVSS vector {} is malformed; Skipping", vector, e);
            return Optional.empty();
        }

        return Optional.of(VulnerabilityRating.newBuilder()
                .setMethod(method)
                .setSource(Source.newBuilder().setName(SOURCE).build())
                .setVector(cvss.getVector())
                .setScore(cvss.calculateScore().getBaseScore())
                .setSeverity(calculateCvssSeverity(cvss))
                .build());
    }

    private static Severity calculateCvssSeverity(final Cvss cvss) {
        if (cvss == null) {
            return SEVERITY_UNKNOWN;
        }

        final double baseScore = cvss.calculateScore().getBaseScore();
        if (cvss instanceof CvssV3) {
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

    /**
     * This function tries to compute a unique ID of a {@link Csaf.Document}, so we can set
     * it as a primary key for a CSAF document in the database.
     * We use the prefix "CSAF" plus a truncated hash of the publisher namespace and the tracking ID.
     *
     * @param doc the doc
     * @return the ID
     */
    public static String computeDocumentId(Csaf.Document doc) throws NoSuchAlgorithmException {
        var digest = MessageDigest.getInstance("SHA-256");

        return "CSAF-" + HexFormat.of().formatHex(
                digest.digest(
                        doc.getPublisher().getNamespace().toString().getBytes()
                )).substring(0, 8) + "-" + doc.getTracking().getId();
    }

    /**
     * This function tries to compute a (unique) ID for this {@link Csaf.Vulnerability},
     * so we can set it as an identifier for the {@link Vulnerability} in the {@link Bom}.
     * As a prefix, the ID generated by {@link ModelConverter#computeDocumentId(Csaf.Document)} is used.
     *
     * @return a (hopefully) unique ID.
     */
    public static String computeVulnerabilityId(Csaf.Vulnerability vuln, Csaf.Document doc, int vulnIndex) throws NoSuchAlgorithmException {
        var prefix = computeDocumentId(doc);

        // If we have a CVE, we can use that as the ID
        var cve = vuln.getCve();
        if (cve != null) {
            return prefix + "-" + cve;
        }

        // If there are unique IDs, we can just use them
        var ids = vuln.getIds();
        if (ids != null) {
            return prefix + "-" + ids.stream().map(Csaf.Id::getText).collect(Collectors.joining("-"));
        }

        // Otherwise, we will use the index of the vulnerability
        return prefix + "-VULNERABILITY" + vulnIndex;
    }


}
