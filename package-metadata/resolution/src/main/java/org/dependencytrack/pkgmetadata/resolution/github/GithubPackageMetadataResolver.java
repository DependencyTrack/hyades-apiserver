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
package org.dependencytrack.pkgmetadata.resolution.github;

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

final class GithubPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    GithubPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final byte[] latestBody = fetchLatestRelease(purl.getNamespace(), purl.getName(), repository);
        if (latestBody == null) {
            return null;
        }

        final JsonNode root = parseJson(latestBody);
        final String tagName = root.path("tag_name").asText(null);
        if (tagName == null) {
            return null;
        }

        final var resolvedAt = Instant.now();

        PackageArtifactMetadata artifactMetadata = null;
        if (purl.getVersion() != null && purl.getVersion().equals(tagName)) {
            artifactMetadata = extractArtifactMetadata(root, resolvedAt);
        } else if (purl.getVersion() != null) {
            final byte[] versionBody = fetchReleaseByTag(
                    purl.getNamespace(), purl.getName(), purl.getVersion(), repository);
            if (versionBody != null) {
                artifactMetadata = extractArtifactMetadata(parseJson(versionBody), resolvedAt);
            }
        }

        return new PackageMetadata(tagName, resolvedAt, artifactMetadata);
    }

    private byte @Nullable [] fetchLatestRelease(
            String owner,
            String name,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "repos", owner, name, "releases", "latest");
        return fetch(url, repository);
    }

    private byte @Nullable [] fetchReleaseByTag(
            String owner,
            String name,
            String tag,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "repos", owner, name, "releases", "tags", tag);
        return fetch(url, repository);
    }

    private byte @Nullable [] fetch(String url, PackageRepository repository) throws InterruptedException {
        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/vnd.github+json")
                .GET();

        if (repository.password() != null) {
            requestBuilder.header("Authorization", "Bearer " + repository.password());
        }

        return cachingHttpClient.get(requestBuilder, repository);
    }

    private static @Nullable PackageArtifactMetadata extractArtifactMetadata(JsonNode root, Instant resolvedAt) {
        final String publishedAtStr = root.path("published_at").asText(null);
        if (publishedAtStr == null) {
            return null;
        }

        try {
            final Instant publishedAt = Instant.parse(publishedAtStr);
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

}
