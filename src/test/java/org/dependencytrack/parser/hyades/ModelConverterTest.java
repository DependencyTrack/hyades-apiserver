package org.dependencytrack.parser.hyades;

import com.google.protobuf.Timestamp;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.CweImporter;
import org.hyades.proto.vuln.v1.Alias;
import org.hyades.proto.vuln.v1.Rating;
import org.hyades.proto.vuln.v1.Reference;
import org.junit.Before;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.hyades.proto.vuln.v1.ScoreMethod.SCORE_METHOD_OWASP;
import static org.hyades.proto.vuln.v1.Source.SOURCE_GITHUB;
import static org.hyades.proto.vuln.v1.Source.SOURCE_NVD;
import static org.hyades.proto.vuln.v1.Source.SOURCE_OSSINDEX;
import static org.hyades.proto.vuln.v1.Source.SOURCE_SNYK;
import static org.hyades.proto.vuln.v1.Source.SOURCE_UNSPECIFIED;

public class ModelConverterTest extends PersistenceCapableTest {

    @Before
    public void setUp() throws Exception {
        new CweImporter().processCweDefinitions();
    }

    @Test
    public void testConvertNullValue() {
        assertThat(ModelConverter.convert((org.hyades.proto.vuln.v1.Vulnerability) null)).isNull();
    }

    @Test
    public void testConvert() {
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("CVE-2021-44228")
                .setSource(SOURCE_NVD)
                .setTitle("Foo Bar")
                .setDescription("Foo Bar Baz Qux Quux")
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV2)
                        .setSource(SOURCE_NVD)
                        .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)")
                        .setScore(9.3))
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_NVD)
                        .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
                        .setScore(10.0))
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV3)
                        .setSource(SOURCE_SNYK)
                        .setVector("snykVector"))
                .setCreated(Timestamp.newBuilder()
                        .setSeconds(1639098000)) // 2021-12-10
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(1639098000)) // 2021-12-10
                .setUpdated(Timestamp.newBuilder()
                        .setSeconds(1675645200)) // 2023-02-06
                .addReferences(Reference.newBuilder()
                        .setUrl("https://logging.apache.org/log4j/2.x/security.html"))
                .addReferences(Reference.newBuilder()
                        .setUrl("https://support.apple.com/kb/HT213189")
                        .setDisplayName("Apple"))
                .addAllCwes(List.of(20, 400, 502, 917, 9999999)) // 9999999 is invalid
                .addAliases(Alias.newBuilder()
                        .setId("SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720")
                        .setSource(SOURCE_SNYK))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2021-44228");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getTitle()).isEqualTo("Foo Bar");
        assertThat(vuln.getDescription()).isEqualTo("Foo Bar Baz Qux Quux");
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo(BigDecimal.valueOf(10.0));
        assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:N/AC:M/Au:N/C:C/I:C/A:C)");
        assertThat(vuln.getCvssV2BaseScore()).isEqualTo(BigDecimal.valueOf(9.3));
        assertThat(vuln.getCreated()).isInSameDayAs("2021-12-10");
        assertThat(vuln.getPublished()).isInSameDayAs("2021-12-10");
        assertThat(vuln.getUpdated()).isInSameDayAs("2023-02-06");
        assertThat(vuln.getReferences()).isEqualToIgnoringWhitespace("""
                * [https://logging.apache.org/log4j/2.x/security.html](https://logging.apache.org/log4j/2.x/security.html)\s
                * [Apple](https://support.apple.com/kb/HT213189)
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
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SNYK-PYTHON-DJANGO-2968205")
                .setSource(SOURCE_SNYK)
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_NVD)
                        .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
                        .setScore(8.8))
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_SNYK)
                        .setVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L")
                        .setScore(7))
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_UNSPECIFIED)
                        .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
                        .setScore(8.8))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("SNYK-PYTHON-DJANGO-2968205");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L");
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
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SNYK-PYTHON-DJANGO-2968205")
                .setSource(SOURCE_SNYK)
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_UNSPECIFIED)
                        .setScore(8.8))
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_UNSPECIFIED)
                        .setVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L")
                        .setScore(7))
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_UNSPECIFIED)
                        .setScore(8.8))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("SNYK-PYTHON-DJANGO-2968205");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("7.0");
        assertThat(vuln.getCvssV3ImpactSubScore()).isEqualTo("4.7");
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualTo("2.2");
    }

    @Test
    public void testConvertWithNoRatings() {
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("Foo")
                .setSource(SOURCE_OSSINDEX)
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
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
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SONATYPE-001")
                .setSource(SOURCE_OSSINDEX)
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV2)
                        .setSource(SOURCE_NVD)
                        .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_OWASP)
                        .setSource(SOURCE_GITHUB)
                        .setVector("SL:1/M:4/O:4/S:9/ED:7/EE:3/A:4/ID:3/LC:9/LI:1/LAV:5/LAC:1/FD:3/RD:4/NC:7/PV:9"))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
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
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("SONATYPE-001")
                .setSource(SOURCE_OSSINDEX)
                .addRatings(Rating.newBuilder()
                        .setSource(SOURCE_NVD)
                        .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln).isNotNull();
    }

    @Test
    public void testConvertWithInvalidCVSSv31() {
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("CVE-001")
                .setSource(SOURCE_NVD)
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV31)
                        .setSource(SOURCE_NVD)
                        .setVector("invalid"))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-001");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
    }

    @Test
    public void testConvertWithInvalidCVSSv3() {
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("CVE-001")
                .setSource(SOURCE_NVD)
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV3)
                        .setSource(SOURCE_NVD)
                        .setVector("invalid"))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-001");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
    }

    @Test
    public void testConvertWithInvalidCVSSv2() {
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("CVE-001")
                .setSource(SOURCE_NVD)
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV2)
                        .setSource(SOURCE_NVD)
                        .setVector("invalid"))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-001");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
    }

    @Test
    public void testConvertWithInvalidOWASPRR() {
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("CVE-001")
                .setSource(SOURCE_NVD)
                .addRatings(Rating.newBuilder()
                        .setMethod(SCORE_METHOD_OWASP)
                        .setSource(SOURCE_NVD)
                        .setVector("invalid"))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-001");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
    }

}