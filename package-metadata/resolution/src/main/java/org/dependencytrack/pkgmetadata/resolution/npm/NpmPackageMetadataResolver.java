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
package org.dependencytrack.pkgmetadata.resolution.npm;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.pkgmetadata.resolution.npm.NpmPackageDocument.PackageInfo;
import org.dependencytrack.pkgmetadata.resolution.npm.NpmPackageDocument.VersionInfo;
import org.dependencytrack.pkgmetadata.resolution.support.CacheKeys;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.Base64;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import static java.io.OutputStream.nullOutputStream;
import static java.util.Objects.requireNonNull;

final class NpmPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(NpmPackageMetadataResolver.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final String PACKAGE_CACHE_KEY_SUFFIX = ":latest";
    private static final String VERSION_CACHE_KEY_SUFFIX = ":v:";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final JsonFactory jsonFactory;
    private final Cache cache;

    NpmPackageMetadataResolver(HttpClient httpClient, ObjectMapper objectMapper, Cache cache) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.jsonFactory = objectMapper.getFactory();
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String packageName = formatPackageName(purl);
        final String cacheKeyBase = CacheKeys.build(repository, packageName);
        final String latestVersionKey = cacheKeyBase + PACKAGE_CACHE_KEY_SUFFIX;
        final String versionKey = cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + purl.getVersion();

        final Map<String, byte[]> cached = cache.getMany(Set.of(latestVersionKey, versionKey));
        final byte[] latestVersionBytes = cached.get(latestVersionKey);
        final byte[] versionMetaBytes = cached.get(versionKey);

        if (latestVersionBytes != null && versionMetaBytes != null) {
            final PackageInfo latest = deserialize(latestVersionBytes, PackageInfo.class);
            final VersionInfo versionInfo = deserialize(versionMetaBytes, VersionInfo.class);

            final byte[] latestVersionMetaBytes = latest != null
                    ? cache.get(cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + latest.version())
                    : null;
            final var latestVersionPublishedAt = latestVersionMetaBytes != null
                    ? deserialize(latestVersionMetaBytes, VersionInfo.class).publishedAt()
                    : null;

            return buildResult(latest.version(), latestVersionPublishedAt, latest.resolvedAt(), versionInfo);
        }

        final NpmPackageDocument doc = fetchAndParseDocument(packageName, repository);
        if (doc == null) {
            return null;
        }

        final Instant resolvedAt = Instant.now();
        final var entriesToCache = new HashMap<String, byte[]>(1 + doc.versions().size());
        if (doc.latestVersion() != null) {
            entriesToCache.put(latestVersionKey,
                    serialize(new PackageInfo(resolvedAt, doc.latestVersion())));
        }
        for (final Map.Entry<String, VersionInfo> entry : doc.versions().entrySet()) {
            final VersionInfo vi = entry.getValue();
            if (vi.shasum() != null || vi.integrity() != null || vi.publishedAt() != null) {
                entriesToCache.put(cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + entry.getKey(),
                        serialize(vi));
            }
        }
        if (!entriesToCache.isEmpty()) {
            cache.putMany(entriesToCache);
        }

        final VersionInfo versionInfo = doc.versions().get(purl.getVersion());
        final VersionInfo latestVersionInfo = doc.versions().get(doc.latestVersion());
        return buildResult(doc.latestVersion(),
                latestVersionInfo != null ? latestVersionInfo.publishedAt() : null,
                resolvedAt,
                versionInfo);
    }

    private static String formatPackageName(PackageURL purl) {
        return purl.getNamespace() != null
                ? purl.getNamespace() + "/" + purl.getName()
                : purl.getName();
    }

    private @Nullable NpmPackageDocument fetchAndParseDocument(
            String packageName,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), packageName);

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Accept-Encoding", "gzip")
                .GET();

        if (repository.password() != null) {
            requestBuilder.header("Authorization", "Bearer " + repository.password());
        }

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(
                    requestBuilder.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (HttpTimeoutException e) {
            throw new RetryableResolutionException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        try (final InputStream responseBodyStream = response.body()) {
            if (response.statusCode() == 200) {
                final boolean isGzip = response.headers()
                        .firstValue("Content-Encoding")
                        .map("gzip"::equalsIgnoreCase)
                        .orElse(false);
                try (final var parser = jsonFactory.createParser(
                        isGzip ? new GZIPInputStream(responseBodyStream) : responseBodyStream)) {
                    return NpmPackageDocument.parseFrom(parser);
                }
            }

            responseBodyStream.transferTo(nullOutputStream());
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

    private static @Nullable PackageMetadata buildResult(
            @Nullable String latestVersion,
            @Nullable Instant latestVersionPublishedAt,
            Instant resolvedAt, @Nullable VersionInfo versionInfo) {
        Instant publishedAt = null;
        var hashes = new EnumMap<HashAlgorithm, String>(HashAlgorithm.class);

        if (versionInfo != null) {
            publishedAt = versionInfo.publishedAt();
            if (versionInfo.shasum() != null) {
                hashes.put(HashAlgorithm.SHA1, versionInfo.shasum());
            }
            if (versionInfo.integrity() != null) {
                try {
                    final byte[] decoded = Base64.getDecoder().decode(versionInfo.integrity());
                    hashes.put(HashAlgorithm.SHA512, HexFormat.of().formatHex(decoded));
                } catch (IllegalArgumentException e) {
                    LOGGER.debug("Failed to decode SHA-512 from base64", e);
                }
            }
        }

        if (latestVersion == null && publishedAt == null && hashes.isEmpty()) {
            return null;
        }

        final PackageArtifactMetadata artifactMetadata = (versionInfo != null)
                ? new PackageArtifactMetadata(resolvedAt, publishedAt, hashes)
                : null;

        return new PackageMetadata(
                latestVersion,
                latestVersionPublishedAt,
                resolvedAt,
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
