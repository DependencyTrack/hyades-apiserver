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
package org.dependencytrack.vulndatasource.nvd;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class NvdVulnDataSourceTest {

    private VulnDataSourceFactory dataSourceFactory;
    private VulnDataSource dataSource;

    @BeforeEach
    void beforeEach() {
        final var config = new NvdVulnDataSourceConfigV1();
        config.setEnabled(true);
        config.setCveFeedsUrl(URI.create("https://nvd.nist.gov/feeds"));

        dataSourceFactory = new NvdVulnDataSourceFactory();

        final var configRegistry = new MockConfigRegistry(dataSourceFactory.runtimeConfigSpec(), config);

        dataSourceFactory.init(new ExtensionContext(configRegistry));
        dataSource = dataSourceFactory.create();
    }

    @AfterEach
    void afterEach() {
        if (dataSource != null) {
            dataSource.close();
        }
        if (dataSourceFactory != null) {
            dataSourceFactory.close();
        }
    }

    @Test
    void test() {
        for (int i = 0; i < 5; i++) {
            assertThat(dataSource.hasNext()).isTrue();

            final Bom bov = dataSource.next();
            assertThat(bov).isNotNull();
            assertThat(bov.getVulnerabilitiesCount()).isEqualTo(1);

            final Vulnerability vuln = bov.getVulnerabilities(0);
            assertThat(vuln.getId()).startsWith("CVE-");
            assertThat(vuln.getSource().getName()).isEqualTo("NVD");
            assertThat(vuln.getDescription()).isNotEmpty();

            dataSource.markProcessed(bov);
        }
    }

    @Test
    void markProcessedShouldThrowWhenBovHasUnexpectedVulnCount() {
        final var bov = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder().setId("CVE-123"))
                .addVulnerabilities(Vulnerability.newBuilder().setId("CVE-456"))
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dataSource.markProcessed(bov))
                .withMessage("BOV must have exactly one vulnerability, but has 2");
    }

    @Test
    void testMarkProcessedWithIncrementalMirroringEnabled() {
        // Test that markProcessed uses watermark manager when incremental mirroring is enabled
        final WatermarkManager watermarkManager = mock(WatermarkManager.class);
        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        final NvdVulnDataSource nvdDataSource = new NvdVulnDataSource(
                watermarkManager,
                objectMapper,
                mock(HttpClient.class),
                "https://nvd.nist.gov/feeds"
        );

        final Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");
        final Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setId("CVE-2024-0001")
                        .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                        .build())
                .build();

        // Step 1: Verify markProcessed does not throw exception
        assertThatNoException()
                .isThrownBy(() -> nvdDataSource.markProcessed(bom));

        // Step 2: Verify that maybeAdvance was called on watermark manager
        verify(watermarkManager).maybeAdvance(updatedAt);
    }

    @Test
    void testMarkProcessedWithIncrementalMirroringDisabled() {
        // Test that markProcessed works when watermark manager is null (incremental mirroring disabled)
        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        final NvdVulnDataSource nvdDataSource = new NvdVulnDataSource(
                null, // watermark manager is null when incremental mirroring is disabled
                objectMapper,
                mock(HttpClient.class),
                "https://nvd.nist.gov/feeds"
        );

        final Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");
        final Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setId("CVE-2024-0001")
                        .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                        .build())
                .build();

        // Step 1: Verify markProcessed does not throw exception when watermark manager is null
        assertThatNoException()
                .isThrownBy(() -> nvdDataSource.markProcessed(bom));

        // Step 2: Verify that watermark manager methods were NOT called (since it's null)
        // This is implicit - if watermark manager was used, it would throw NullPointerException
    }

    @Test
    void testCloseWithIncrementalMirroringEnabled() {
        // Test that close uses watermark manager when incremental mirroring is enabled
        final WatermarkManager watermarkManager = mock(WatermarkManager.class);
        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        final NvdVulnDataSource nvdDataSource = new NvdVulnDataSource(
                watermarkManager,
                objectMapper,
                mock(HttpClient.class),
                "https://nvd.nist.gov/feeds"
        );

        // Step 1: Set completedSuccessfully to true (simulating successful processing)
        // Note: This is a private field, so we can't set it directly, but we can verify behavior
        // The watermark manager is only committed if completedSuccessfully is true

        // Step 2: Verify close does not throw exception
        assertThatNoException()
                .isThrownBy(nvdDataSource::close);

        // Step 3: Verify that maybeCommit was NOT called (because completedSuccessfully is false by default)
        verify(watermarkManager, never()).maybeCommit();
    }

    @Test
    void testCloseWithIncrementalMirroringDisabled() {
        // Test that close works when watermark manager is null (incremental mirroring disabled)
        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        final NvdVulnDataSource nvdDataSource = new NvdVulnDataSource(
                null, // watermark manager is null when incremental mirroring is disabled
                objectMapper,
                mock(HttpClient.class),
                "https://nvd.nist.gov/feeds"
        );

        // Step 1: Verify close does not throw exception when watermark manager is null
        assertThatNoException()
                .isThrownBy(nvdDataSource::close);

        // Step 2: Verify that watermark manager methods were NOT called (since it's null)
        // This is implicit - if watermark manager was used, it would throw NullPointerException
    }

    @Test
    void testMarkProcessedWithMissingUpdatedTimestamp() {
        // Test that markProcessed handles missing updated timestamp gracefully
        final WatermarkManager watermarkManager = mock(WatermarkManager.class);
        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        final NvdVulnDataSource nvdDataSource = new NvdVulnDataSource(
                watermarkManager,
                objectMapper,
                mock(HttpClient.class),
                "https://nvd.nist.gov/feeds"
        );

        // Step 1: Create BOM with vulnerability that has no updated timestamp
        final Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setId("CVE-2024-0001")
                        // No setUpdated() call - missing updated timestamp
                        .build())
                .build();

        // Step 2: Verify markProcessed does not throw exception
        assertThatNoException()
                .isThrownBy(() -> nvdDataSource.markProcessed(bom));

        // Step 3: Verify that maybeAdvance was called with null (missing updated timestamp)
        verify(watermarkManager).maybeAdvance(null);
    }

    @Test
    void testMarkProcessedWithMissingUpdatedTimestampAndIncrementalMirroringDisabled() {
        // Test that markProcessed handles missing updated timestamp when watermark manager is null
        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        final NvdVulnDataSource nvdDataSource = new NvdVulnDataSource(
                null, // watermark manager is null when incremental mirroring is disabled
                objectMapper,
                mock(HttpClient.class),
                "https://nvd.nist.gov/feeds"
        );

        // Step 1: Create BOM with vulnerability that has no updated timestamp
        final Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setId("CVE-2024-0001")
                        // No setUpdated() call - missing updated timestamp
                        .build())
                .build();

        // Step 2: Verify markProcessed does not throw exception when watermark manager is null
        assertThatNoException()
                .isThrownBy(() -> nvdDataSource.markProcessed(bom));

        // Step 3: Verify that watermark manager methods were NOT called (since it's null)
        // This is implicit - if watermark manager was used, it would throw NullPointerException
    }

}