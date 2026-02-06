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

import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionTestCheck;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class NvdVulnDataSourceFactoryTest extends AbstractExtensionFactoryTest<@NonNull VulnDataSource, @NonNull NvdVulnDataSourceFactory> {

    protected NvdVulnDataSourceFactoryTest() {
        super(NvdVulnDataSourceFactory.class);
    }

    @Nested
    @WireMockTest
    class TestMethodTest {

        @Test
        void shouldPassConnectivityAndFeedFormatCheck(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(get(urlPathEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                    .willReturn(aResponse()
                            .withBody("""
                                    lastModifiedDate:2026-01-19T16:00:01-05:00
                                    size:15114674
                                    zipSize:1674794
                                    gzSize:1674650
                                    sha256:482399306951B6FF9E00E3EC72A7EED8D927FB2DB4F4E61F2D6218CF67133CC0
                                    """)));

            factory.init(
                    new ExtensionContext(
                            new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true"))));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isFalse();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.PASSED);
                        assertThat(check.message()).isNull();
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.PASSED);
                        assertThat(check.message()).isNull();
                    });
        }

        @Test
        void shouldReportConnectionFailure(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(get(urlPathEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                    .willReturn(aResponse()
                            .withFault(Fault.CONNECTION_RESET_BY_PEER)));

            factory.init(
                    new ExtensionContext(
                            new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true"))));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.FAILED);
                        assertThat(check.message()).isEqualTo("Connection failed, check logs for details");
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    });
        }

        @Test
        void shouldReportConnectionFailureWhenLocalConnectionsAreDisallowed(WireMockRuntimeInfo wmRuntimeInfo) {
            factory.init(
                    new ExtensionContext(
                            new MockConfigRegistry(
                                    Map.of("allow-local-connections", "false"))));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.FAILED);
                        assertThat(check.message()).isEqualTo("Connection to local hosts is not allowed");
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    });
        }

        @Test
        void shouldReportInvalidFeedFormatFailure(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(get(urlPathEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                    .willReturn(aResponse()
                            .withBody("invalid")));

            factory.init(
                    new ExtensionContext(
                            new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true"))));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.PASSED);
                        assertThat(check.message()).isNull();
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.FAILED);
                        assertThat(check.message()).isEqualTo("Failed to parse feed metadata, check logs for details");
                    });
        }

        @Test
        void shouldReportAllChecksSkippedWhenDisabled(WireMockRuntimeInfo wmRuntimeInfo) {
            factory.init(
                    new ExtensionContext(
                            new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true"))));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(false)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isFalse();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    });
        }

    }

    @Test
    void createShouldCreateWatermarkManagerWhenIncrementalMirroringEnabled() throws Exception {
        final var config = (NvdVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(true); // Explicitly enable incremental mirroring

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        // Step 1: Create data source
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(dataSource).isInstanceOf(NvdVulnDataSource.class);

        // Step 2: Verify watermark manager is NOT null when incremental mirroring is enabled
        final NvdVulnDataSource nvdDataSource = (NvdVulnDataSource) dataSource;
        final Field watermarkManagerField = NvdVulnDataSource.class.getDeclaredField("watermarkManager");
        watermarkManagerField.setAccessible(true);
        final Object watermarkManager = watermarkManagerField.get(nvdDataSource);
        assertThat(watermarkManager)
                .as("Watermark manager should be created when incremental mirroring is enabled")
                .isNotNull();

        // Step 3: Verify data source can be closed without errors
        assertThatNoException()
                .isThrownBy(dataSource::close);
    }

    @Test
    void createShouldNotCreateWatermarkManagerWhenIncrementalMirroringDisabled() throws Exception {
        final var config = (NvdVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(false); // Disable incremental mirroring

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        // Step 1: Create data source
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(dataSource).isInstanceOf(NvdVulnDataSource.class);

        // Step 2: Verify watermark manager IS null when incremental mirroring is disabled
        final NvdVulnDataSource nvdDataSource = (NvdVulnDataSource) dataSource;
        final Field watermarkManagerField = NvdVulnDataSource.class.getDeclaredField("watermarkManager");
        watermarkManagerField.setAccessible(true);
        final Object watermarkManager = watermarkManagerField.get(nvdDataSource);
        assertThat(watermarkManager)
                .as("Watermark manager should be null when incremental mirroring is disabled")
                .isNull();

        // Step 3: Verify data source can be closed without errors (no watermark manager to commit)
        assertThatNoException()
                .isThrownBy(dataSource::close);
    }

    @Test
    void createShouldDefaultToIncrementalMirroringEnabled() throws Exception {
        final var config = (NvdVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        // Don't set incrementalMirroringEnabled - should default to true

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        // Step 1: Create data source with default config (incremental mirroring not explicitly set)
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(dataSource).isInstanceOf(NvdVulnDataSource.class);

        // Step 2: Verify watermark manager is NOT null by default (incremental mirroring enabled by default)
        final NvdVulnDataSource nvdDataSource = (NvdVulnDataSource) dataSource;
        final Field watermarkManagerField = NvdVulnDataSource.class.getDeclaredField("watermarkManager");
        watermarkManagerField.setAccessible(true);
        final Object watermarkManager = watermarkManagerField.get(nvdDataSource);
        assertThat(watermarkManager)
                .as("Watermark manager should be created by default (incremental mirroring enabled by default)")
                .isNotNull();

        // Step 3: Verify default config value is true
        assertThat(config.isIncrementalMirroringEnabled())
                .as("Default value of incrementalMirroringEnabled should be true")
                .isTrue();

        // Step 4: Verify data source can be closed without errors
        assertThatNoException()
                .isThrownBy(dataSource::close);
    }

}