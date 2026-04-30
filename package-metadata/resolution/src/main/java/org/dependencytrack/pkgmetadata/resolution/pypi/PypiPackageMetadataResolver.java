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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.pkgmetadata.resolution.support.CacheKeys;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class PypiPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final String PACKAGE_CACHE_KEY_SUFFIX = ":latest";
    private static final String VERSION_CACHE_KEY_SUFFIX = ":v:";
    private static final PypiVersionMetadata EMPTY_VERSION_METADATA = new PypiVersionMetadata(null, null);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Cache cache;

    PypiPackageMetadataResolver(HttpClient httpClient, ObjectMapper objectMapper, Cache cache) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String fileName = purl.getQualifiers() != null
                ? purl.getQualifiers().get("file_name") : null;

        final String cacheKeyBase = CacheKeys.build(repository, purl.getName());
        final String packageMetadataCacheKey = cacheKeyBase + PACKAGE_CACHE_KEY_SUFFIX;
        final String versionMetadataCacheKey = fileName != null
                ? cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + purl.getVersion() + ":" + fileName
                : null;

        final var cacheKeys = new HashSet<String>(2);
        cacheKeys.add(packageMetadataCacheKey);
        if (versionMetadataCacheKey != null) {
            cacheKeys.add(versionMetadataCacheKey);
        }

        final Map<String, byte[]> cached = cache.getMany(cacheKeys);
        final byte[] cachedPackageMetadataBytes = cached.get(packageMetadataCacheKey);
        final byte[] cachedVersionMetadataBytes = versionMetadataCacheKey != null
                ? cached.get(versionMetadataCacheKey)
                : null;

        if (cachedPackageMetadataBytes != null && (versionMetadataCacheKey == null || cachedVersionMetadataBytes != null)) {
            final var packageMeta = deserialize(cachedPackageMetadataBytes, PypiPackageMetadata.class);
            final var versionMeta = cachedVersionMetadataBytes != null
                    ? deserialize(cachedVersionMetadataBytes, PypiVersionMetadata.class)
                    : null;
            return buildResult(packageMeta.latestVersion(), packageMeta.resolvedAt(), versionMeta);
        }

        final PypiPackageDocument doc = fetchDocument(purl, repository);
        if (doc == null) {
            return null;
        }

        final String latestVersion = doc.info() != null ? doc.info().version() : null;
        final Map<String, List<PypiPackageDocument.ReleaseFile>> releases =
                doc.releases() != null ? doc.releases() : Map.of();

        final Instant resolvedAt = Instant.now();
        final var entriesToCache = new HashMap<String, byte[]>();
        if (latestVersion != null) {
            entriesToCache.put(packageMetadataCacheKey,
                    serialize(new PypiPackageMetadata(resolvedAt, latestVersion)));
        }

        PypiVersionMetadata matchedVersionMeta = null;
        final List<PypiPackageDocument.ReleaseFile> releaseFiles = releases.get(purl.getVersion());
        if (releaseFiles != null) {
            for (final PypiPackageDocument.ReleaseFile file : releaseFiles) {
                final var fileMeta = extractFileMetadata(file);
                if (fileMeta == null || file.filename() == null) {
                    continue;
                }

                entriesToCache.put(
                        cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + purl.getVersion() + ":" + file.filename(),
                        serialize(fileMeta));

                if (file.filename().equals(fileName)) {
                    matchedVersionMeta = fileMeta;
                }
            }
        }

        // Negative-cache when the requested file_name didn't match any release file,
        // to avoid re-fetching the full document on subsequent lookups.
        if (versionMetadataCacheKey != null && matchedVersionMeta == null) {
            entriesToCache.put(versionMetadataCacheKey, serialize(EMPTY_VERSION_METADATA));
        }

        if (!entriesToCache.isEmpty()) {
            cache.putMany(entriesToCache);
        }

        return buildResult(latestVersion, resolvedAt, matchedVersionMeta);
    }

    private @Nullable PypiPackageDocument fetchDocument(
            PackageURL purl,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "pypi", purl.getName(), "json");

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            throw new RetryableResolutionException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        try {
            if (response.statusCode() == 404) {
                return null;
            }
            RetryableResolutionException.throwIfRetryableError(response);
            if (response.statusCode() != 200) {
                throw new IOException("Unexpected status code %d for %s".formatted(response.statusCode(), url));
            }
            return objectMapper.readValue(response.body(), PypiPackageDocument.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static @Nullable PypiVersionMetadata extractFileMetadata(PypiPackageDocument.ReleaseFile file) {
        if (file.digests() == null) {
            return null;
        }

        final String md5 = file.digests().md5();
        final String sha256 = file.digests().sha256();

        if (md5 == null && sha256 == null) {
            return null;
        }

        return new PypiVersionMetadata(md5, sha256);
    }

    private static @Nullable PackageMetadata buildResult(
            @Nullable String latestVersion,
            Instant resolvedAt,
            @Nullable PypiVersionMetadata versionMeta) {
        if (latestVersion == null && versionMeta == null) {
            return null;
        }

        PackageArtifactMetadata artifactMetadata = null;
        if (versionMeta != null && (versionMeta.md5() != null || versionMeta.sha256() != null)) {
            final var hashes = new EnumMap<HashAlgorithm, String>(HashAlgorithm.class);
            if (versionMeta.md5() != null) {
                hashes.put(HashAlgorithm.MD5, versionMeta.md5());
            }
            if (versionMeta.sha256() != null) {
                hashes.put(HashAlgorithm.SHA256, versionMeta.sha256());
            }
            artifactMetadata = new PackageArtifactMetadata(resolvedAt, null, hashes);
        }

        return new PackageMetadata(latestVersion, null, resolvedAt, artifactMetadata);
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
