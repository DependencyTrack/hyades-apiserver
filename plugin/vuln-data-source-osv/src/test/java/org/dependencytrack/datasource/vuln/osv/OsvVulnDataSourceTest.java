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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import net.javacrumbs.jsonunit.core.Option;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class OsvVulnDataSourceTest {

    private WatermarkManager watermarkManagerMock;
    private OsvVulnDataSource vulnDataSource;
    private ObjectMapper objectMapper;

    @BeforeEach
    void beforeEach() throws Exception {
        watermarkManagerMock = mock(WatermarkManager.class);
        objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        URL url = URI.create("http://localhost").toURL();

        vulnDataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                url,
                List.of("maven"),
                mock(HttpClient.class),
                false
        );
    }

    @Test
    void testAdvanceWatermarkWhenProcessed() {
        Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                        .addProperties(Property.newBuilder()
                                .setName(CycloneDxPropertyNames.PROPERTY_OSV_ECOSYSTEM)
                                .setValue("maven"))
                        .build())
                .build();

        vulnDataSource.markProcessed(bom);
        verify(watermarkManagerMock)
                .maybeAdvance(eq("maven"), eq(updatedAt));
    }

    @Test
    void testExceptionWithMultipleVulns() {
        Vulnerability v1 = Vulnerability.newBuilder().build();
        Vulnerability v2 = Vulnerability.newBuilder().build();

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(v1)
                .addVulnerabilities(v2)
                .build();

        assertThatThrownBy(() -> vulnDataSource.markProcessed(bom))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("BOV must have exactly one vulnerability, but has 2");
    }

    @Test
    void testExceptionWhenMissingEcosystem() {
        Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");

        Vulnerability vuln = Vulnerability.newBuilder()
                .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                .build();

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(vuln)
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> vulnDataSource.markProcessed(bom));
    }

    @Test
    void testExceptionWhenMissingUpdated() {
        Vulnerability vuln = Vulnerability.newBuilder()
                .addProperties(Property.newBuilder()
                        .setName(CycloneDxPropertyNames.PROPERTY_OSV_ECOSYSTEM)
                        .setValue("maven"))
                .build();

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(vuln)
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> vulnDataSource.markProcessed(bom));
    }

    @Test
    void testCloseWithCompletedEcosystems() {
        vulnDataSource.close();
        verify(watermarkManagerMock).maybeCommit(any(Set.class));
    }

    @Test
    void testDownloadAndExtractEcosystemFiles() throws Exception {

        var wireMockServer = new WireMockServer();
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());
        final String ecosystem = "maven";

        // Create in-memory ZIP with one advisory JSON
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBytes)) {
            ZipEntry entry = new ZipEntry("osv-advisory.json");
            zos.putNextEntry(entry);
            String advisoryJson = """
                {
                    "id": "OSV-789",
                    "summary": "Test vulnerability",
                    "affected": [],
                    "modified": "2022-06-09T07:01:32.587163Z"
                }
                """;
            zos.write(advisoryJson.getBytes());
            zos.closeEntry();
        }

        stubFor(get(urlEqualTo("/" + ecosystem + "/all.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(zipBytes.toByteArray())
                        .withHeader("Content-Type", "application/zip")));

        URL url = new URL("http://localhost:" + wireMockServer.port());

        OsvVulnDataSource dataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                url,
                List.of(ecosystem),
                HttpClient.newHttpClient(),
                false
        );

        assertTrue(dataSource.hasNext());
        var bom = dataSource.next();
        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "vulnerabilities" : [
                                {
                                     "id" : "OSV-789",
                                     "source" : {
                                       "name" : "OSV"
                                     },
                                     "ratings" : [ {
                                       "severity" : "SEVERITY_UNKNOWN"
                                     } ],
                                     "updated": "2022-06-09T07:01:32Z",
                                     "properties" : [
                                         {
                                           "name" : "dependency-track:vuln:title",
                                           "value" : "Test vulnerability"
                                         },
                                         {
                                            "name": "internal:osv:ecosystem",
                                            "value": "maven"
                                         }
                                     ]
                                }
                           ]
                        }
        """);

        dataSource.markProcessed(bom);
        verify(watermarkManagerMock).maybeAdvance(eq(ecosystem), any());

        dataSource.close();
        verify(watermarkManagerMock).maybeCommit(any());
    }

}