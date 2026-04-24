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
package org.dependencytrack.pkgmetadata.resolution.gem;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class GemPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(GemPackageMetadataResolver.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Cache cache;

    GemPackageMetadataResolver(HttpClient httpClient, ObjectMapper objectMapper, Cache cache) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(PackageURL purl, @Nullable PackageRepository repository)
            throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String cacheKey = CacheKeys.build(repository, purl.getName());

        byte[] body = cache.get(cacheKey);
        if (body == null) {
            body = fetchVersions(purl.getName(), repository);
            if (body == null) {
                return null;
            }
            cache.put(cacheKey, body);
        }

        final JsonNode root = parseJson(body);
        if (!root.isArray() || root.isEmpty()) {
            return null;
        }

        final String latestVersion = root.get(0).path("number").asText(null);
        if (latestVersion == null) {
            return null;
        }
        Instant latestVersionPublishedAt = getCreatedAt(root.get(0));

        final String requestedVersion = purl.getVersion();
        JsonNode matchingEntry = null;
        for (int i = 0; i < root.size(); i++) {
            if (requestedVersion.equals(root.get(i).path("number").asText(null))) {
                matchingEntry = root.get(i);
                break;
            }
        }

        final var resolvedAt = Instant.now();
        if (matchingEntry == null) {
            return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, null);
        }

        Instant publishedAt = latestVersion.equals(requestedVersion)
                ? latestVersionPublishedAt
                : getCreatedAt(matchingEntry);

        return new PackageMetadata(
                latestVersion,
                latestVersionPublishedAt,
                resolvedAt,
                publishedAt != null
                        ? new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of())
                        : null);
    }

    private @Nullable Instant getCreatedAt(JsonNode entry) {
        final String createdAt = entry.path("created_at").asText(null);
        if (createdAt != null) {
            try {
                return Instant.parse(createdAt);
            } catch (DateTimeParseException e) {
                LOGGER.debug("Failed to parse created_at '{}'", createdAt, e);
            }
        }
        return null;
    }

    private byte @Nullable [] fetchVersions(String name, PackageRepository repository)
            throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "api", "v1", "versions", name + ".json");

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

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
