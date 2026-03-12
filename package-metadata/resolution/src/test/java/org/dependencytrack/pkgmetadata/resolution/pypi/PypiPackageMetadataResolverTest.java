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
package org.dependencytrack.pkgmetadata.resolution.pypi;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class PypiPackageMetadataResolverTest {

    private static final String PYPI_RESPONSE = /* language=JSON */ """
            {
              "info": {
                "version": "2.0.0"
              },
              "releases": {
                "1.0.0": [{
                  "filename": "mypackage-1.0.0.tar.gz",
                  "digests": {
                    "md5": "aaaa1111bbbb2222cccc3333dddd4444",
                    "sha256": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
                  }
                }, {
                  "filename": "mypackage-1.0.0-py3-none-any.whl",
                  "digests": {
                    "md5": "bbbb2222cccc3333dddd4444eeee5555",
                    "sha256": "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333"
                  }
                }],
                "2.0.0": [{
                  "filename": "mypackage-2.0.0.tar.gz",
                  "digests": {
                    "md5": "1111222233334444555566667777aaaa",
                    "sha256": "1111222233334444555566667777aaaa8888bbbb9999cccc0000ddddeeee1111"
                  }
                }]
              }
            }
            """;

    private PypiPackageMetadataResolverFactory factory;
    private PypiPackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        factory = new PypiPackageMetadataResolverFactory();
        factory.init(new ExtensionContext(new MockConfigRegistry(Map.of(), null, null, null)));
        resolver = (PypiPackageMetadataResolver) factory.create();
    }

    @AfterEach
    void afterEach() {
        if (factory != null) {
            factory.close();
        }
    }

    @Test
    void shouldResolveHashesWhenFileNameQualifierMatches(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "mypackage-1.0.0.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.MD5, "aaaa1111bbbb2222cccc3333dddd4444")
                .containsEntry(HashAlgorithm.SHA256, "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222");
    }

    @Test
    void shouldResolveHashesForCorrectFileWhenMultipleFilesExist(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "mypackage-1.0.0-py3-none-any.whl")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.MD5, "bbbb2222cccc3333dddd4444eeee5555")
                .containsEntry(HashAlgorithm.SHA256, "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333");
    }

    @Test
    void shouldNotResolveHashesWhenNoFileNameQualifier(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldNotResolveHashesWhenFileNameDoesNotMatch(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "nonexistent-file.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldNegativeCacheUnmatchedFileName(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final var cachingResolver = createResolverWithCache();

        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "nonexistent-file.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        cachingResolver.resolve(purl, repo);

        final PackageMetadata secondResult = cachingResolver.resolve(purl, repo);
        assertThat(secondResult).isNotNull();
        assertThat(secondResult.latestVersion()).isEqualTo("2.0.0");
        assertThat(secondResult.artifactMetadata()).isNull();

        verify(1, getRequestedFor(urlPathEqualTo("/pypi/mypackage/json")));
    }

    private static PypiPackageMetadataResolver createResolverWithCache() {
        final var objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        final var store = new ConcurrentHashMap<String, byte[]>();
        final var cache = new Cache() {
            @Override
            public byte[] get(String key, Function<String, byte[]> loader) {
                return store.computeIfAbsent(key, loader);
            }

            @Override
            public Map<String, byte[]> getMany(Set<String> keys) {
                final var result = new HashMap<String, byte[]>();
                for (final String key : keys) {
                    final byte[] value = store.get(key);
                    if (value != null) {
                        result.put(key, value);
                    }
                }
                return result;
            }

            @Override
            public void put(String key, byte[] value) {
                if (value != null) {
                    store.put(key, value);
                }
            }

            @Override
            public void putMany(Map<String, byte[]> entries) {
                entries.forEach((k, v) -> { if (v != null) store.put(k, v); });
            }

            @Override
            public void invalidateMany(Set<String> keys) {
                keys.forEach(store::remove);
            }

            @Override
            public void invalidateAll() {
                store.clear();
            }
        };
        return new PypiPackageMetadataResolver(HttpClient.newHttpClient(), objectMapper, cache);
    }

    @Test
    void shouldReturnNullWhenPackageNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/nonexistent/json"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
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
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "15")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(15));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

    @Test
    void shouldReturnNoHashesWhenVersionNotInReleases(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("99.99.99")
                .withQualifier("file_name", "mypackage-99.99.99.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

}
