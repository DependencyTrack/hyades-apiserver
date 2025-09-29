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

import com.google.protobuf.Timestamp;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.datasource.vuln.osv.schema.OsvSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * @since 5.7.0
 */
final class ModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ModelConverter.class);
    private static final Source SOURCE = Source.newBuilder().setName("OSV").build();
    private static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";

    private ModelConverter() {
    }

    static Bom convert(OsvSchema schemaInput, boolean isAliasSyncEnabled) {
        if (schemaInput.getWithdrawn() != null) {
            return null;
        }

        return Bom.newBuilder()
                .addVulnerabilities(extractVulnerability(schemaInput))
                .build();
    }

    private static Vulnerability extractVulnerability(OsvSchema schemaInput) {
        Vulnerability.Builder vulnerability = Vulnerability.newBuilder();

        Optional.ofNullable(schemaInput.getId()).ifPresent(id -> vulnerability.setId(id));
        vulnerability.setSource(extractSource(schemaInput.getId()));
        Optional.ofNullable(schemaInput.getSummary()).ifPresent(summary -> vulnerability.addProperties(
                Property.newBuilder().setName(TITLE_PROPERTY_NAME).setValue(trimSummary(summary)).build()));
        Optional.ofNullable(schemaInput.getDetails()).ifPresent(details -> vulnerability.setDescription(details));

        Optional.ofNullable(schemaInput.getPublished())
                .map(published -> published.toInstant())
                .map(instant -> Timestamp.newBuilder().setSeconds(instant.getEpochSecond()))
                .ifPresent(vulnerability::setPublished);

        Optional.ofNullable(schemaInput.getModified())
                .map(published -> published.toInstant())
                .map(instant -> Timestamp.newBuilder().setSeconds(instant.getEpochSecond()))
                .ifPresent(vulnerability::setUpdated);

//        if (schemaInput.getDatabaseSpecific() != null) {
//            vulnerability.addAllCwes(osvDto.databaseSpecific().getCwes());
//            //this severity is compared with affected package severities and highest set
//            severity = ParserUtil.mapSeverity(osvDto.databaseSpecific().severity());
//        }
//        if (aliasSyncEnabled) {
//            vulnerability.addAllReferences(osvDto.getAliases());
//        }
//        Optional.ofNullable(osvDto.getCredits()).ifPresent(vulnerability::setCredits);
//        Optional.ofNullable(osvDto.getReferences().get("ADVISORY")).ifPresent(vulnerability::addAllAdvisories);
//        Optional.ofNullable(osvDto.getReferences().get("EXTERNAL")).ifPresent(cyclonedxBom::addAllExternalReferences);
//
//        //affected ranges
//        JSONArray osvAffectedArray = object.optJSONArray("affected");
//        if (osvAffectedArray != null) {
//            // affected packages and versions
//            // low-priority severity assignment
//            vulnerability.addAllAffects(parseAffectedRanges(vulnerability.getId(), osvAffectedArray, cyclonedxBom));
//            severity = parseSeverity(osvAffectedArray);
//        }
//
//        // CVSS ratings
//        vulnerability.addAllRatings(parseCvssRatings(object, severity));

        return vulnerability.build();
    }

    private static String trimSummary(String summary) {
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
}
