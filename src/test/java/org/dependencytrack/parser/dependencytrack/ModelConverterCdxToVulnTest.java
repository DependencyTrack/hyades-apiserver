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

import com.google.protobuf.Timestamp;
import org.cyclonedx.proto.v1_6.Advisory;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.VulnerabilityRating;
import org.cyclonedx.proto.v1_6.VulnerabilityReference;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Vulnerability;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_6.ScoreMethod.SCORE_METHOD_OWASP;

public class ModelConverterCdxToVulnTest extends PersistenceCapableTest {

    @Test
    public void testConvertNullValue() {
        assertThat(ModelConverterCdxToVuln.convert(qm, Bom.newBuilder().build(), null, false)).isNull();
    }

    @Test
    public void testConvert() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_6.Vulnerability.newBuilder()
                        .setId("CVE-2021-44228")
                        .setSource(Source.newBuilder().setName("NVD").build())
                        .setDescription("Foo Bar Description")
                        .setDetail("Foo Bar Baz Qux Quux")
                        .setRecommendation("Do this remedy as a fix")
                        .setCreated(Timestamp.newBuilder()
                                .setSeconds(1639098000)) // 2021-12-10
                        .setPublished(Timestamp.newBuilder()
                                .setSeconds(1639098000)) // 2021-12-10
                        .setUpdated(Timestamp.newBuilder()
                                .setSeconds(1675645200)) // 2023-02-06
                        .addAllCwes(List.of(20, 400, 502, 917, 9999999)) // 9999999 is invalid
                        .addAdvisories(Advisory.newBuilder().setUrl("https://logging.apache.org/log4j/2.x/security.html").build())
                        .addAdvisories(Advisory.newBuilder().setUrl("https://support.apple.com/kb/HT213189").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV2)
                                .setScore(9.3)
                                .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(10.0)
                                .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("SNYK").build())
                                .setMethod(SCORE_METHOD_CVSSV3)
                                .setVector("snykVector"))
                        .addReferences(VulnerabilityReference.newBuilder()
                                .setId("SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720")
                                .setSource(Source.newBuilder().setName("SNYK").build()).build())
                        .addProperties(Property.newBuilder()
                                .setName(ModelConverterCdxToVuln.TITLE_PROPERTY_NAME)
                                .setValue("Foo Bar Title").build())
                        .build()).build();

        final Vulnerability vuln = ModelConverterCdxToVuln.convert(qm, bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2021-44228");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getTitle()).isEqualTo("Foo Bar Title");
        assertThat(vuln.getDescription()).isEqualTo("Foo Bar Description");
        assertThat(vuln.getDetail()).isEqualTo("Foo Bar Baz Qux Quux");
        assertThat(vuln.getRecommendation()).isEqualTo("Do this remedy as a fix");
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo(BigDecimal.valueOf(10.0));
        assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:N/AC:M/Au:N/C:C/I:C/A:C)");
        assertThat(vuln.getCvssV2BaseScore()).isEqualTo(BigDecimal.valueOf(9.3));
        assertThat(vuln.getCreated()).isInSameDayAs("2021-12-10");
        assertThat(vuln.getPublished()).isInSameDayAs("2021-12-10");
        assertThat(vuln.getUpdated()).isInSameDayAs("2023-02-06");
        assertThat(vuln.getReferences()).isEqualToIgnoringWhitespace("""
                * [https://logging.apache.org/log4j/2.x/security.html](https://logging.apache.org/log4j/2.x/security.html)\s
                * [https://support.apple.com/kb/HT213189](https://support.apple.com/kb/HT213189)
                """);
        assertThat(vuln.getCwes()).containsOnly(20, 400, 502, 917);
        assertThat(vuln.getAliases()).satisfiesExactly(
                alias -> {
                    assertThat(alias.getCveId()).isEqualTo("CVE-2021-44228");
                    assertThat(alias.getSnykId()).isEqualTo("SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720");
                }
        );
    }

    @Test
    public void testConvertWithRatingFromSnykAsAuthoritativeSource() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_6.Vulnerability.newBuilder()
                        .setId("SNYK-PYTHON-DJANGO-2968205")
                        .setSource(Source.newBuilder().setName("SNYK").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(8.8)
                                .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("SNYK").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(7)
                                .setVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
                                .setScore(8.8))
                        .build()).build();
        final Vulnerability vuln = ModelConverterCdxToVuln.convert(qm, bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("SNYK-PYTHON-DJANGO-2968205");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("7.0");
        assertThat(vuln.getCvssV3ImpactSubScore()).isEqualTo("4.7");
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualTo("2.2");
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
    }

    @Test
    public void testConvertWithRatingsWithoutVector() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_6.Vulnerability.newBuilder()
                        .setId("SNYK-PYTHON-DJANGO-2968205")
                        .setSource(Source.newBuilder().setName("SNYK").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(8.8))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(7)
                                .setVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setScore(8.8))
                        .build()).build();
        final Vulnerability vuln = ModelConverterCdxToVuln.convert(qm, bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("SNYK-PYTHON-DJANGO-2968205");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("7.0");
        assertThat(vuln.getCvssV3ImpactSubScore()).isEqualTo("4.7");
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualTo("2.2");
    }

    @Test
    public void testConvertWithNoRatings() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_6.Vulnerability.newBuilder()
                        .setId("Foo")
                        .setSource(Source.newBuilder().setName("OSSINDEX").build())
                        .build()).build();
        final Vulnerability vuln = ModelConverterCdxToVuln.convert(qm, bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
    }

    @Test
    public void testConvertWithOnlyThirdPartyRatings() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_6.Vulnerability.newBuilder()
                        .setId("SONATYPE-001")
                        .setSource(Source.newBuilder().setName("OSSINDEX").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV2)
                                .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("GITHUB").build())
                                .setMethod(SCORE_METHOD_OWASP)
                                .setVector("SL:1/M:4/O:4/S:9/ED:7/EE:3/A:4/ID:3/LC:9/LI:1/LAV:5/LAC:1/FD:3/RD:4/NC:7/PV:9"))
                        .build()).build();
        final Vulnerability vuln = ModelConverterCdxToVuln.convert(qm, bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:N/AC:M/Au:N/C:C/I:C/A:C)");
        assertThat(vuln.getCvssV2BaseScore()).isEqualTo(BigDecimal.valueOf(9.3));
        assertThat(vuln.getCvssV2ImpactSubScore()).isEqualTo("10.0");
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isEqualTo("8.6");
        assertThat(vuln.getOwaspRRVector()).isEqualTo("SL:1/M:4/O:4/S:9/ED:7/EE:3/A:4/ID:3/LC:9/LI:1/LAV:5/LAC:1/FD:3/RD:4/NC:7/PV:9");
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isEqualTo("5.75");
        assertThat(vuln.getOwaspRRLikelihoodScore()).isEqualTo("4.375");
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isEqualTo("4.0");
    }

    @Test
    public void testConvertWithRatingWithoutMethod() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_6.Vulnerability.newBuilder()
                        .setId("SONATYPE-001")
                        .setSource(Source.newBuilder().setName("OSSINDEX").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                        .build()).build();
        final Vulnerability vuln = ModelConverterCdxToVuln.convert(qm, bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
    }
}