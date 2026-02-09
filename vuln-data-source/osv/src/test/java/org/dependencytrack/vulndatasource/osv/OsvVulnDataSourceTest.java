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
package org.dependencytrack.vulndatasource.osv;

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
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OsvVulnDataSourceTest {

    private WatermarkManager watermarkManagerMock;
    private OsvVulnDataSource vulnDataSource;
    private ObjectMapper objectMapper;

    @BeforeEach
    void beforeEach() {
        watermarkManagerMock = mock(WatermarkManager.class);
        objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        vulnDataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                "http://localhost",
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
    void testNoExceptionWhenMissingUpdated() {
        Vulnerability vuln = Vulnerability.newBuilder()
                .addProperties(Property.newBuilder()
                        .setName(CycloneDxPropertyNames.PROPERTY_OSV_ECOSYSTEM)
                        .setValue("maven"))
                .build();

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(vuln)
                .build();

        assertThatNoException()
                .isThrownBy(() -> vulnDataSource.markProcessed(bom));

        verify(watermarkManagerMock, never()).maybeAdvance(eq("maven"), any(Instant.class));
    }

    @Test
    void testCloseWithCompletedEcosystems() {
        vulnDataSource.close();
        verify(watermarkManagerMock).maybeCommit(any(Set.class));
    }

    @Test
    void testIncrementalMirroringEnabledUsesWatermark() throws Exception {
        // Test that when incremental mirroring is enabled, watermark manager is used
        final WatermarkManager watermarkManager = mock(WatermarkManager.class);
        final String ecosystem = "maven";
        final Instant existingWatermark = Instant.parse("2024-01-01T12:00:00Z");

        // Mock watermark manager to return an existing watermark
        when(watermarkManager.getWatermark(ecosystem)).thenReturn(existingWatermark);

        var wireMockServer = new WireMockServer(options().dynamicPort());
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());

        // Stub for incremental download (modified IDs CSV endpoint)
        stubFor(get(urlEqualTo("/" + ecosystem + "/modified_id.csv"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("")
                        .withHeader("Content-Type", "text/csv")));

        OsvVulnDataSource dataSource = new OsvVulnDataSource(
                watermarkManager,
                objectMapper,
                "http://localhost:" + wireMockServer.port(),
                List.of(ecosystem),
                HttpClient.newHttpClient(),
                false
        );

        // Step 1: When hasNext() is called, it should check for watermark
        dataSource.hasNext();

        // Step 2: Verify that getWatermark was called (incremental mirroring enabled)
        verify(watermarkManager).getWatermark(ecosystem);

        // Step 3: Verify that all.zip was NOT requested (incremental download should be used instead)
        WireMock.verify(0, getRequestedFor(urlEqualTo("/" + ecosystem + "/all.zip")));

        // Step 4: Verify that modified_id.csv endpoint was requested (incremental download path)
        WireMock.verify(getRequestedFor(urlEqualTo("/" + ecosystem + "/modified_id.csv")));

        // Step 5: Verify close calls maybeCommit on watermark manager
        dataSource.close();
        verify(watermarkManager).maybeCommit(any(Set.class));

        wireMockServer.stop();
    }

    @Test
    void testIncrementalMirroringEnabledNoWatermarkDownloadsAll() throws Exception {
        // Test that when incremental mirroring is enabled but no watermark exists, all files are downloaded
        final WatermarkManager watermarkManager = mock(WatermarkManager.class);
        final String ecosystem = "maven";

        // Mock watermark manager to return null (no existing watermark)
        when(watermarkManager.getWatermark(ecosystem)).thenReturn(null);

        var wireMockServer = new WireMockServer(options().dynamicPort());
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());

        // Create in-memory ZIP for all.zip download
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBytes)) {
            ZipEntry entry = new ZipEntry("osv-advisory.json");
            zos.putNextEntry(entry);
            String advisoryJson = """
                {
                    "id": "OSV-789",
                    "summary": "Test vulnerability",
                    "affected": [],
                    "modified": "2022-06-09T07:01:32.587Z"
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

        OsvVulnDataSource dataSource = new OsvVulnDataSource(
                watermarkManager,
                objectMapper,
                "http://localhost:" + wireMockServer.port(),
                List.of(ecosystem),
                HttpClient.newHttpClient(),
                false
        );

        // Step 1: When hasNext() is called, it should check for watermark
        dataSource.hasNext();

        // Step 2: Verify that getWatermark was called (watermark manager is used)
        verify(watermarkManager).getWatermark(ecosystem);

        // Step 3: Verify that all.zip was requested (download all when no watermark exists)
        WireMock.verify(getRequestedFor(urlEqualTo("/" + ecosystem + "/all.zip")));

        // Step 4: Verify that modified_id.csv endpoint was NOT requested (no incremental download when no watermark)
        WireMock.verify(0, getRequestedFor(urlEqualTo("/" + ecosystem + "/modified_id.csv")));

        // Step 5: Verify close calls maybeCommit on watermark manager
        dataSource.close();
        verify(watermarkManager).maybeCommit(any(Set.class));

        wireMockServer.stop();
    }

    @Test
    void testIncrementalMirroringDisabledDownloadsAll() throws Exception {
        // Test that when incremental mirroring is disabled, all files are downloaded and watermark is not used
        final String ecosystem = "maven";

        var wireMockServer = new WireMockServer(options().dynamicPort());
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());

        // Create in-memory ZIP for all.zip download
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBytes)) {
            ZipEntry entry = new ZipEntry("osv-advisory.json");
            zos.putNextEntry(entry);
            String advisoryJson = """
                {
                    "id": "OSV-789",
                    "summary": "Test vulnerability",
                    "affected": [],
                    "modified": "2022-06-09T07:01:32.587Z"
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

        // Create data source WITHOUT watermark manager (incremental mirroring disabled)
        OsvVulnDataSource dataSource = new OsvVulnDataSource(
                null, // watermark manager is null when incremental mirroring is disabled
                objectMapper,
                "http://localhost:" + wireMockServer.port(),
                List.of(ecosystem),
                HttpClient.newHttpClient(),
                false
        );

        // Step 1: When hasNext() is called, it should download all files directly (no watermark check)
        dataSource.hasNext();

        // Step 2: Verify that all.zip was requested (download all when incremental mirroring is disabled)
        WireMock.verify(getRequestedFor(urlEqualTo("/" + ecosystem + "/all.zip")));

        // Step 3: Verify that modified_id.csv endpoint was NOT requested (incremental download not used)
        WireMock.verify(0, getRequestedFor(urlEqualTo("/" + ecosystem + "/modified_id.csv")));

        // Step 4: Test markProcessed - should not call watermark manager and should not throw exception
        Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");
        Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                        .addProperties(Property.newBuilder()
                                .setName(CycloneDxPropertyNames.PROPERTY_OSV_ECOSYSTEM)
                                .setValue(ecosystem))
                        .build())
                .build();

        assertThatNoException()
                .isThrownBy(() -> dataSource.markProcessed(bom));

        // Step 5: Test close - should not call watermark manager and should not throw exception
        assertThatNoException()
                .isThrownBy(dataSource::close);

        wireMockServer.stop();
    }

    @Test
    void testMarkProcessedWithIncrementalMirroringDisabled() {
        // Test that markProcessed works when watermark manager is null (incremental mirroring disabled)
        OsvVulnDataSource dataSourceWithoutWatermark = new OsvVulnDataSource(
                null, // watermark manager is null when incremental mirroring is disabled
                objectMapper,
                "http://localhost",
                List.of("maven"),
                mock(HttpClient.class),
                false
        );

        Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                        .addProperties(Property.newBuilder()
                                .setName(CycloneDxPropertyNames.PROPERTY_OSV_ECOSYSTEM)
                                .setValue("maven"))
                        .build())
                .build();

        // Step 1: Verify markProcessed does not throw exception when watermark manager is null
        assertThatNoException()
                .isThrownBy(() -> dataSourceWithoutWatermark.markProcessed(bom));

        // Step 2: Verify that watermark manager methods were NOT called (since it's null)
        // This is implicit - if watermark manager was used, it would throw NullPointerException
    }

    @Test
    void testCloseWithIncrementalMirroringDisabled() {
        // Test that close works when watermark manager is null (incremental mirroring disabled)
        OsvVulnDataSource dataSourceWithoutWatermark = new OsvVulnDataSource(
                null, // watermark manager is null when incremental mirroring is disabled
                objectMapper,
                "http://localhost",
                List.of("maven"),
                mock(HttpClient.class),
                false
        );

        // Step 1: Verify close does not throw exception when watermark manager is null
        assertThatNoException()
                .isThrownBy(dataSourceWithoutWatermark::close);

        // Step 2: Verify that watermark manager methods were NOT called (since it's null)
        // This is implicit - if watermark manager was used, it would throw NullPointerException
    }

    @Test
    void testDownloadAndExtractEcosystemFiles() throws Exception {

        var wireMockServer = new WireMockServer(options().dynamicPort());
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
                    "modified": "2022-06-09T07:01:32.587Z"
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

        OsvVulnDataSource dataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                "http://localhost:" + wireMockServer.port(),
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
                                     "updated": "2022-06-09T07:01:32.587Z",
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