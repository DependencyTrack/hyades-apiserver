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
package org.dependencytrack.pkgmetadata.resolution.gomodules;

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

final class GoModulesPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Cache cache;

    GoModulesPackageMetadataResolver(HttpClient httpClient, ObjectMapper objectMapper, Cache cache) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        String modulePath = purl.getName();
        if (purl.getNamespace() != null) {
            // NB: A few modules do not have a namespace, such as
            // the standard library, e.g. pkg:golang/stdlib@1.26.0.
            modulePath = purl.getNamespace() + "/" + modulePath;
        }

        final String cacheKey = CacheKeys.build(repository, modulePath);

        byte[] body = cache.get(cacheKey);
        if (body == null) {
            body = fetchModule(modulePath, repository);
            if (body == null) {
                return null;
            }
            cache.put(cacheKey, body);
        }

        final JsonNode root = parseJson(body);
        final String latestVersion = root.path("Version").asText(null);
        if (latestVersion == null) {
            return null;
        }

        final var resolvedAt = Instant.now();
        final var latestVersionPublishedAt = extractPublishedAt(root);

        PackageArtifactMetadata artifactMetadata = null;
        if (purl.getVersion().equals(latestVersion)) {
            artifactMetadata = new PackageArtifactMetadata(resolvedAt, latestVersionPublishedAt, Map.of());
        } else {
            final String versionCacheKey = CacheKeys.build(repository, modulePath, purl.getVersion());
            byte[] versionBody = cache.get(versionCacheKey);
            if (versionBody == null) {
                versionBody = fetchVersionInfo(modulePath, purl.getVersion(), repository);
                if (versionBody != null) {
                    cache.put(versionCacheKey, versionBody);
                }
            }
            if (versionBody != null) {
                artifactMetadata = new PackageArtifactMetadata(resolvedAt, extractPublishedAt(parseJson(versionBody)), Map.of());
            }
        }

        return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, artifactMetadata);
    }

    private byte @Nullable [] fetchModule(
            String modulePath,
            PackageRepository repository) throws InterruptedException {
        final String[] moduleSegments = modulePath.split("/");
        final String url = UrlUtils.join(UrlUtils.join(repository.url(), moduleSegments), "@latest");

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

    private byte @Nullable [] fetchVersionInfo(
            String modulePath,
            String version,
            PackageRepository repository) throws InterruptedException {
        final String[] moduleSegments = modulePath.split("/");
        final String url = UrlUtils.join(
                UrlUtils.join(repository.url(), moduleSegments), "@v", version + ".info");

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

        RetryableResolutionException.throwIfRetryableError(response);
        if (response.statusCode() != 200) {
            return null;
        }
        return response.body();
    }

    private static @Nullable Instant extractPublishedAt(JsonNode root) {
        final String time = root.path("Time").asText(null);
        if (time == null) {
            return null;
        }

        try {
            return Instant.parse(time);
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
