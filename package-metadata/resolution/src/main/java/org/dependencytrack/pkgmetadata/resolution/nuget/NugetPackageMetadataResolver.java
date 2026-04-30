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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
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
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import static java.io.OutputStream.nullOutputStream;
import static java.util.Objects.requireNonNull;

final class NugetPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final String PACKAGE_CACHE_KEY_SUFFIX = ":latest";
    private static final String VERSION_CACHE_KEY_SUFFIX = ":v:";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Cache cache;

    NugetPackageMetadataResolver(HttpClient httpClient, ObjectMapper objectMapper, Cache cache) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String cacheKeyBase = CacheKeys.build(repository, purl.getName().toLowerCase());
        final String latestVersionKey = cacheKeyBase + PACKAGE_CACHE_KEY_SUFFIX;
        final String versionKey = purl.getVersion() != null
                ? cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + purl.getVersion()
                : null;

        final var keysToLookup = new LinkedHashSet<String>(2);
        keysToLookup.add(latestVersionKey);
        if (versionKey != null) {
            keysToLookup.add(versionKey);
        }

        final Map<String, byte[]> cached = cache.getMany(keysToLookup);
        final byte[] latestVersionBytes = cached.get(latestVersionKey);
        final byte[] versionMetaBytes = versionKey != null ? cached.get(versionKey) : null;

        if (latestVersionBytes != null && (versionKey == null || versionMetaBytes != null)) {
            final var packageMeta = deserialize(latestVersionBytes, NugetPackageMetadata.class);

            final String latestVersionMetaKey = packageMeta.latestVersion() != null
                    ? cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + packageMeta.latestVersion()
                    : null;
            final byte[] latestVersionMetaBytes = latestVersionMetaKey != null ? cache.get(latestVersionMetaKey) : null;
            final var latestVersionMeta = latestVersionMetaBytes != null
                    ? deserialize(latestVersionMetaBytes, NugetVersionMetadata.class) : null;

            final var versionMeta = versionMetaBytes != null
                    ? deserialize(versionMetaBytes, NugetVersionMetadata.class) : null;

            return buildResult(packageMeta.latestVersion(),
                    latestVersionMeta != null ? latestVersionMeta.publishedAt() : null,
                    packageMeta.resolvedAt(),
                    versionMeta != null ? versionMeta.publishedAt() : null);
        }

        final JsonNode root = fetchDocument(purl, repository);
        if (root == null) {
            return null;
        }

        final JsonNode items = root.path("items");
        if (!items.isArray() || items.isEmpty()) {
            return null;
        }

        // Navigate to last page -> last item -> catalogEntry -> version for latest.
        final JsonNode lastPage = items.get(items.size() - 1);
        final JsonNode lastPageItems = lastPage.path("items");
        if (!lastPageItems.isArray() || lastPageItems.isEmpty()) {
            return null;
        }

        final JsonNode lastItem = lastPageItems.get(lastPageItems.size() - 1);
        final String latestVersion = lastItem.path("catalogEntry").path("version").asText(null);
        if (latestVersion == null) {
            return null;
        }

        // Extract published timestamps for all versions and cache them.
        final Instant resolvedAt = Instant.now();
        final var entriesToCache = new HashMap<String, byte[]>();
        entriesToCache.put(latestVersionKey,
                serialize(new NugetPackageMetadata(resolvedAt, latestVersion)));

        Instant requestedVersionPublishedAt = null;
        Instant latestVersionPublishedAt = null;
        for (final JsonNode page : items) {
            final JsonNode pageItems = page.path("items");
            if (!pageItems.isArray()) {
                continue;
            }
            for (final JsonNode item : pageItems) {
                final JsonNode catalogEntry = item.path("catalogEntry");
                final String version = catalogEntry.path("version").asText(null);
                final String published = catalogEntry.path("published").asText(null);
                if (version == null || published == null) {
                    continue;
                }

                final Instant publishedAt = parsePublished(published);
                if (publishedAt != null) {
                    entriesToCache.put(cacheKeyBase + VERSION_CACHE_KEY_SUFFIX + version,
                            serialize(new NugetVersionMetadata(publishedAt)));
                    if (purl.getVersion() != null && version.equals(purl.getVersion())) {
                        requestedVersionPublishedAt = publishedAt;
                    }
                    if (latestVersion != null && version.equals(latestVersion)) {
                        latestVersionPublishedAt = publishedAt;
                    }
                }
            }
        }

        if (!entriesToCache.isEmpty()) {
            cache.putMany(entriesToCache);
        }

        return buildResult(latestVersion, latestVersionPublishedAt, resolvedAt, requestedVersionPublishedAt);
    }

    private @Nullable JsonNode fetchDocument(
            PackageURL purl,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(),
                "v3", "registration5-gz-semver2", purl.getName().toLowerCase(), "index.json");

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
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

        final boolean isGzip = response.headers()
                .firstValue("Content-Encoding")
                .map("gzip"::equalsIgnoreCase)
                .orElse(false);

        try (final InputStream rawBody = response.body();
             final InputStream body = isGzip ? new GZIPInputStream(rawBody) : rawBody) {
            if (response.statusCode() == 200) {
                return objectMapper.readTree(body);
            }

            body.transferTo(nullOutputStream());
            RetryableResolutionException.throwIfRetryableError(response);

            if (response.statusCode() == 404) {
                return null;
            }

            throw new IOException("Unexpected status code %d for %s"
                    .formatted(response.statusCode(), url));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static @Nullable Instant parsePublished(String published) {
        try {
            return Instant.parse(published);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static @Nullable PackageMetadata buildResult(
            String latestVersion,
            Instant latestVersionPublishedAt,
            Instant resolvedAt,
            @Nullable Instant publishedAt) {
        final PackageArtifactMetadata artifactMetadata = publishedAt != null
                ? new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of())
                : null;

        return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, artifactMetadata);
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
