package org.dependencytrack.parser.hyades;

import com.google.protobuf.Timestamp;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.CweImporter;
import org.hyades.proto.vuln.v1.Alias;
import org.hyades.proto.vuln.v1.Rating;
import org.hyades.proto.vuln.v1.Reference;
import org.hyades.proto.vuln.v1.ScoreMethod;
import org.hyades.proto.vuln.v1.Source;
import org.junit.Before;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class ModelConverterTest extends PersistenceCapableTest {

    @Before
    public void setUp() throws Exception {
        new CweImporter().processCweDefinitions();
    }

    @Test
    public void testConvertNullValue() {
        assertThat(ModelConverter.convert(null)).isNull();
    }

    @Test
    public void testConvert() {
        final var hyadesVuln = org.hyades.proto.vuln.v1.Vulnerability.newBuilder()
                .setId("CVE-2021-44228")
                .setSource(Source.SOURCE_NVD)
                .setTitle("Foo Bar")
                .setDescription("Foo Bar Baz Qux Quux")
                .addRatings(Rating.newBuilder()
                        .setMethod(ScoreMethod.SCORE_METHOD_CVSSV31)
                        .setSource(Source.SOURCE_NVD)
                        .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
                        .setScore(10.0))
                .addRatings(Rating.newBuilder()
                        .setMethod(ScoreMethod.SCORE_METHOD_CVSSV2)
                        .setSource(Source.SOURCE_NVD)
                        .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)")
                        .setScore(9.3))
                .addRatings(Rating.newBuilder()
                        .setMethod(ScoreMethod.SCORE_METHOD_CVSSV3)
                        .setSource(Source.SOURCE_SNYK)
                        .setVector("snykVector"))
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
                        .setSource(Source.SOURCE_SNYK))
                .build();

        final Vulnerability vuln = ModelConverter.convert(hyadesVuln);
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2021-44228");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getTitle()).isEqualTo("Foo Bar");
        assertThat(vuln.getDescription()).isEqualTo("Foo Bar Baz Qux Quux");
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo(BigDecimal.valueOf(10.0));
        assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:N/AC:M/Au:N/C:C/I:C/A:C)");
        assertThat(vuln.getCvssV2BaseScore()).isEqualTo(BigDecimal.valueOf(9.3));
        assertThat(vuln.getCreated()).isNull();
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

}