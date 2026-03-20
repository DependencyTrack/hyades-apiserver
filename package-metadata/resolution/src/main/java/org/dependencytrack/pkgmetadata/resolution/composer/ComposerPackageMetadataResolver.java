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
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class ComposerPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Cache cache;

    ComposerPackageMetadataResolver(HttpClient httpClient, ObjectMapper objectMapper, Cache cache) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String packageKey = purl.getNamespace() + "/" + purl.getName();
        final String cacheKey = CacheKeys.build(repository, packageKey);

        byte[] body = cache.get(cacheKey);
        if (body == null) {
            body = fetchPackage(packageKey, repository);
            if (body == null) {
                return null;
            }
            cache.put(cacheKey, body);
        }

        final JsonNode root = parseJson(body);
        final JsonNode packages = root.path("packages").path(packageKey);
        if (!packages.isArray() || packages.isEmpty()) {
            return null;
        }

        // Find latest stable version (no dev/alpha/beta/RC suffix).
        String latestVersion = null;
        for (final JsonNode entry : packages) {
            final String version = entry.path("version").asText(null);
            if (version == null) {
                continue;
            }
            if (!version.contains("dev") && !version.contains("alpha")
                    && !version.contains("beta") && !version.contains("RC")) {
                latestVersion = version;
                break;
            }
        }

        if (latestVersion == null && !packages.isEmpty()) {
            latestVersion = packages.get(0).path("version").asText(null);
        }

        if (latestVersion == null) {
            return null;
        }

        final var resolvedAt = Instant.now();

        PackageArtifactMetadata artifactMetadata = null;
        if (purl.getVersion() != null) {
            for (final JsonNode entry : packages) {
                if (purl.getVersion().equals(entry.path("version").asText(null))) {
                    artifactMetadata = extractArtifactMetadata(entry, resolvedAt);
                    break;
                }
            }
        }

        return new PackageMetadata(latestVersion, resolvedAt, artifactMetadata);
    }

    private byte @Nullable [] fetchPackage(String packageKey, PackageRepository repository)
            throws InterruptedException {
        final String baseUrl = trimTrailingSlash(repository.url());
        final String url = baseUrl + "/p2/" + packageKey + ".json";

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<byte[]> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (HttpTimeoutException e) {
            throw new RetryableResolutionException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        if (response.statusCode() == 404) {
            return null;
        }
        RetryableResolutionException.throwIfRetryableError(response);
        if (response.statusCode() != 200) {
            throw new UncheckedIOException(new IOException(
                    "Unexpected status code %d for %s".formatted(response.statusCode(), url)));
        }
        return response.body();
    }

    private static @Nullable PackageArtifactMetadata extractArtifactMetadata(
            JsonNode entry,
            Instant resolvedAt) {
        final String time = entry.path("time").asText(null);
        if (time == null) {
            return null;
        }

        try {
            final Instant publishedAt = OffsetDateTime.parse(time).toInstant();
            return new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of());
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

}
