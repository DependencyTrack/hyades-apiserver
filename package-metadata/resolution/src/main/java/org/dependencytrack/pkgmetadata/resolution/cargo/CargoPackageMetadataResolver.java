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
package org.dependencytrack.pkgmetadata.resolution.cargo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.pkgmetadata.resolution.cargo.CargoCrateDocument.Version;
import org.dependencytrack.pkgmetadata.resolution.support.CacheKeys;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import static java.io.OutputStream.nullOutputStream;
import static java.util.Objects.requireNonNull;

final class CargoPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final String PACKAGE_CACHE_KEY_SUFFIX = ":latest";
    private static final String VERSION_CACHE_KEY_SUFFIX = ":v:";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Cache cache;

    CargoPackageMetadataResolver(HttpClient httpClient, ObjectMapper objectMapper, Cache cache) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final var cacheKeyPrefix = CacheKeys.build(repository, purl.getName());
        final var crateMetadataCacheKey = cacheKeyPrefix + PACKAGE_CACHE_KEY_SUFFIX;
        final var versionMetadataCacheKey = cacheKeyPrefix + VERSION_CACHE_KEY_SUFFIX + purl.getVersion();
        final var cacheKeys = Set.of(crateMetadataCacheKey, versionMetadataCacheKey);

        final Map<String, byte[]> cachedBytesByKey = cache.getMany(cacheKeys);
        final byte[] cachedCrateBytes = cachedBytesByKey.get(crateMetadataCacheKey);
        final byte[] cachedVersionBytes = cachedBytesByKey.get(versionMetadataCacheKey);

        if (cachedCrateBytes != null && cachedVersionBytes != null) {
            final var crateMetadata = deserialize(cachedCrateBytes, CargoCrateMetadata.class);
            final var versionMetadata = deserialize(cachedVersionBytes, CargoCrateVersionMetadata.class);
            return buildResult(crateMetadata, versionMetadata);
        }

        final CargoCrateDocument crateDoc = fetchCrate(purl.getName(), repository);
        if (crateDoc == null) {
            return null;
        }

        final String latestVersion = crateDoc.crate() != null
                ? crateDoc.crate().newestVersion()
                : null;
        if (latestVersion == null) {
            return null;
        }

        final var resolvedAt = Instant.now();
        Instant latestVersionPublishedAt = null;
        final var entriesToCache = new HashMap<String, byte[]>(
                1 + (crateDoc.versions() != null ? crateDoc.versions().size() : 0));

        CargoCrateVersionMetadata requestedVersionMetadata = null;
        if (crateDoc.versions() != null) {
            for (final Version crateVersion : crateDoc.versions()) {
                if (crateVersion.num() == null) {
                    continue;
                }

                final var versionMetadata = CargoCrateVersionMetadata.of(crateVersion);
                if (versionMetadata != null) {
                    entriesToCache.put(
                            cacheKeyPrefix + VERSION_CACHE_KEY_SUFFIX + crateVersion.num(),
                            serialize(versionMetadata));
                }

                if (crateVersion.num().equals(purl.getVersion())) {
                    requestedVersionMetadata = versionMetadata;
                }
                if (crateVersion.num().equals(latestVersion)) {
                    latestVersionPublishedAt = versionMetadata.publishedAt();
                }
            }
        }

        final var crateMetadata = new CargoCrateMetadata(resolvedAt, latestVersion, latestVersionPublishedAt);
        entriesToCache.put(crateMetadataCacheKey, serialize(crateMetadata));

        cache.putMany(entriesToCache);

        return buildResult(crateMetadata, requestedVersionMetadata);
    }

    private @Nullable CargoCrateDocument fetchCrate(String name, PackageRepository repository)
            throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "api", "v1", "crates", name);

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept-Encoding", "gzip")
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (HttpTimeoutException e) {
            throw new RetryableResolutionException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        try (final InputStream rawBody = response.body()) {
            if (response.statusCode() == 200) {
                final boolean isGzip = response.headers()
                        .firstValue("Content-Encoding")
                        .map("gzip"::equalsIgnoreCase)
                        .orElse(false);
                try (final InputStream body = isGzip ? new GZIPInputStream(rawBody) : rawBody) {
                    return objectMapper.readValue(body, CargoCrateDocument.class);
                }
            }

            rawBody.transferTo(nullOutputStream());
            RetryableResolutionException.throwIfRetryableError(response);

            if (response.statusCode() == 404) {
                return null;
            }

            throw new IOException(
                    "Unexpected status code %d for %s".formatted(
                            response.statusCode(), url));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static PackageMetadata buildResult(
            CargoCrateMetadata crateMetadata,
            @Nullable CargoCrateVersionMetadata versionMetadata) {
        PackageArtifactMetadata artifactMetadata = null;
        if (versionMetadata != null) {
            artifactMetadata = new PackageArtifactMetadata(
                    crateMetadata.resolvedAt(),
                    versionMetadata.publishedAt(),
                    versionMetadata.sha256() != null
                            ? Map.of(HashAlgorithm.SHA256, versionMetadata.sha256())
                            : Map.of());
        }

        return new PackageMetadata(
                crateMetadata.latestVersion(),
                crateMetadata.latestVersionPublishedAt(),
                crateMetadata.resolvedAt(),
                artifactMetadata);
    }

    private byte[] serialize(Object value) {
        try {
            return objectMapper.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private <T> T deserialize(byte[] bytes, Class<T> type) {
        try {
            return objectMapper.readValue(bytes, type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
