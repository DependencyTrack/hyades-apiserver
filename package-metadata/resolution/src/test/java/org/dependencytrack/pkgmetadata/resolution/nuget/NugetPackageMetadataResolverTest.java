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
package org.dependencytrack.pkgmetadata.resolution.nuget;

import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class NugetPackageMetadataResolverTest {

    private static final String NUGET_INDEX_RESPONSE = /* language=JSON */ """
            {
              "items": [{
                "items": [
                  {
                    "catalogEntry": {
                      "version": "1.0.0",
                      "published": "2023-06-15T10:30:00Z"
                    }
                  },
                  {
                    "catalogEntry": {
                      "version": "2.0.0",
                      "published": "2024-01-01T12:00:00Z"
                    }
                  }
                ]
              }]
            }
            """;

    private static final String NUGET_INDEX_PRERELEASE_ONLY_RESPONSE = /* language=JSON */ """
            {
              "items": [{
                "items": [
                  {
                    "catalogEntry": {
                      "version": "1.0.0-beta.1",
                      "published": "2023-06-15T10:30:00Z"
                    }
                  },
                  {
                    "catalogEntry": {
                      "version": "1.0.0-rc.1",
                      "published": "2024-01-01T12:00:00Z"
                    }
                  }
                ]
              }]
            }
            """;

    private NugetPackageMetadataResolverFactory factory;
    private NugetPackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        factory = new NugetPackageMetadataResolverFactory();
        factory.init(
                new MutableServiceRegistry()
                        .register(CacheManager.class, new NoopCacheManager())
                        .register(ConfigRegistry.class, new MockConfigRegistry(Map.of(), null, null, null))
                        .register(HttpClient.class, HttpClient.newHttpClient()));
        resolver = (NugetPackageMetadataResolver) factory.create();
    }

    @AfterEach
    void afterEach() {
        if (factory != null) {
            factory.close();
        }
    }

    @Test
    void shouldResolveLatestVersionAndPublishedAt(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody(NUGET_INDEX_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName("MyPackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt().getEpochSecond())
                .isEqualTo(1686825000L);
        assertThat(result.artifactMetadata().hashes()).isEmpty();
    }

    @Test
    void shouldResolveLatestVersionWithoutPublishedAtWhenVersionNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody(NUGET_INDEX_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName("MyPackage")
                .withVersion("99.99.99")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldResolveLatestVersionWhenOnlyPrereleaseVersionsExist(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody(NUGET_INDEX_PRERELEASE_ONLY_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName("MyPackage")
                .withVersion("1.0.0-beta.1")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0-rc.1");
        assertThat(result.artifactMetadata()).isNotNull();
    }

    @Test
    void shouldReturnNullWhenPackageNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/nonexistent/index.json"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName("MyPackage")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "10")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName("MyPackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(10));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(504)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName("MyPackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

}
