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
package org.dependencytrack.pkgmetadata.resolution.composer;

import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class ComposerPackageMetadataResolverTest {

    private ComposerPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        resolverFactory = new ComposerPackageMetadataResolverFactory();
        resolverFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(), null, null, null)));
        resolver = resolverFactory.create();
    }

    @AfterEach
    void afterEach() {
        if (resolverFactory != null) {
            resolverFactory.close();
        }
    }

    @Test
    void shouldResolveLatestVersionAndPublishedAt(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": [
                              {"version": "v2.1.0-dev", "time": "2024-11-01T10:00:00+00:00"},
                              {"version": "v2.0.0", "time": "2024-10-11T08:11:39+00:00"},
                              {"version": "v1.9.0", "time": "2024-05-01T12:00:00+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("v2.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v2.0.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo("2024-10-11T08:11:39Z");
    }

    @Test
    void shouldFallBackToFirstEntryWhenAllVersionsAreDev(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": [
                              {"version": "v2.1.0-dev", "time": "2024-11-01T10:00:00+00:00"},
                              {"version": "v2.0.0-beta", "time": "2024-10-01T10:00:00+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("v2.1.0-dev")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v2.1.0-dev");
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenVersionNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": [
                              {"version": "v2.0.0", "time": "2024-10-11T08:11:39+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v2.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldReturnNullWhenPackageNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/p2/vendor/nonexistent.json"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = PackageURLBuilder.aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(30));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

}
