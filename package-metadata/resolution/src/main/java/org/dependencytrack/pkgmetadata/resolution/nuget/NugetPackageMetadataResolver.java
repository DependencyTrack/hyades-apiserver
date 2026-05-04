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
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.cache.CachingHttpClient;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class NugetPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    NugetPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String url = UrlUtils.join(repository.url(),
                "v3", "registration5-gz-semver2", purl.getName().toLowerCase(), "index.json");

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        final JsonNode root = parseJson(body);
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

        final Instant resolvedAt = Instant.now();
        final Instant requestedVersionPublishedAt = purl.getVersion() != null
                ? findPublishedAt(items, purl.getVersion())
                : null;

        final PackageArtifactMetadata artifactMetadata = requestedVersionPublishedAt != null
                ? new PackageArtifactMetadata(resolvedAt, requestedVersionPublishedAt, Map.of())
                : null;

        return new PackageMetadata(latestVersion, resolvedAt, artifactMetadata);
    }

    private static @Nullable Instant findPublishedAt(JsonNode items, String version) {
        for (final JsonNode page : items) {
            final JsonNode pageItems = page.path("items");
            if (!pageItems.isArray()) {
                continue;
            }

            for (final JsonNode item : pageItems) {
                final JsonNode catalogEntry = item.path("catalogEntry");
                if (version.equals(catalogEntry.path("version").asText(null))) {
                    final String published = catalogEntry.path("published").asText(null);
                    return published != null ? parsePublished(published) : null;
                }
            }
        }

        return null;
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
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

}
