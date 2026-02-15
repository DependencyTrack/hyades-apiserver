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
package org.dependencytrack.vulnanalysis.ossindex;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @since 5.7.0
 */
final class OssIndexVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(OssIndexVulnAnalyzer.class);
    private static final int OSS_INDEX_BATCH_SIZE = 128;
    private static final int CACHE_BATCH_SIZE = 500;
    private static final Set<String> SUPPORTED_PURL_TYPES = Set.of(
            "cargo",
            "cocoapods",
            "composer",
            "conan",
            "conda",
            "cran",
            "gem",
            "golang",
            "maven",
            "npm",
            "nuget",
            "pypi",
            "rpm",
            "swift");

    private final Cache resultsCache;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI apiUrl;
    private final String username;
    private final String apiToken;

    OssIndexVulnAnalyzer(
            Cache resultsCache,
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiUrl,
            String username,
            String apiToken) {
        this.resultsCache = resultsCache;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.apiUrl = apiUrl;
        this.username = username;
        this.apiToken = apiToken;
    }

    @Override
    public Bom analyze(Bom bom) {
        final var bomRefsByPurl = new LinkedHashMap<String, List<String>>();

        for (final Component component : bom.getComponentsList()) {
            if (component.getPropertiesCount() > 0
                    && component.getPropertiesList().stream()
                    .map(Property::getName)
                    .anyMatch("dependencytrack:internal:is-internal-component"::equalsIgnoreCase)) {
                continue;
            }
            if (component.hasPurl()) {
                try {
                    final var purl = new PackageURL(component.getPurl());
                    if (!SUPPORTED_PURL_TYPES.contains(purl.getType())) {
                        continue;
                    }

                    bomRefsByPurl
                            .computeIfAbsent(purl.getCoordinates(), k -> new ArrayList<>())
                            .add(component.getBomRef());
                } catch (MalformedPackageURLException e) {
                    LOGGER.warn("Failed to parse purl '{}'; Skipping", component.getPurl(), e);
                }
            }
        }

        if (bomRefsByPurl.isEmpty()) {
            LOGGER.debug("No analyzable PURLs found; Skipping analysis");
            return Bom.getDefaultInstance();
        }

        final var componentReports = new ArrayList<ComponentReport>(bomRefsByPurl.size());
        final var purlsToFetch = new LinkedHashSet<>(bomRefsByPurl.keySet());

        for (final var batch : partition(List.copyOf(bomRefsByPurl.keySet()), CACHE_BATCH_SIZE)) {
            final Map<String, byte @Nullable []> cachedBytes = resultsCache.getMany(Set.copyOf(batch));
            for (final var entry : cachedBytes.entrySet()) {
                purlsToFetch.remove(entry.getKey());

                if (entry.getValue() == null) {
                    continue;
                }

                try {
                    componentReports.add(objectMapper.readValue(entry.getValue(), ComponentReport.class));
                } catch (IOException e) {
                    LOGGER.warn(
                            "Failed to deserialize cached component report for coordinates '{}'; Will re-fetch",
                            entry.getKey(), e);
                    purlsToFetch.add(entry.getKey());
                }
            }
        }

        if (!purlsToFetch.isEmpty()) {
            for (final var purlPartition : partition(List.copyOf(purlsToFetch), OSS_INDEX_BATCH_SIZE)) {
                LOGGER.debug("Fetching component reports for {} coordinates", purlPartition.size());

                final List<ComponentReport> batchReports;
                try {
                    batchReports = getComponentReports(purlPartition);
                } catch (IOException e) {
                    throw new UncheckedIOException("Failed to retrieve component report", e);
                }

                final var entriesToCache = new HashMap<String, byte @Nullable []>(purlPartition.size());
                final var fetchedPurls = new HashSet<String>(batchReports.size());

                for (final var report : batchReports) {
                    fetchedPurls.add(report.coordinates());
                    if (report.vulnerabilities() != null && !report.vulnerabilities().isEmpty()) {
                        try {
                            entriesToCache.put(report.coordinates(), objectMapper.writeValueAsBytes(report));
                        } catch (IOException e) {
                            LOGGER.warn("Failed to serialize component report for coordinates '{}'; Skipping cache",
                                    report.coordinates(), e);
                        }
                    } else {
                        entriesToCache.put(report.coordinates(), null);
                    }
                }

                for (final String purl : purlPartition) {
                    if (!fetchedPurls.contains(purl)) {
                        entriesToCache.put(purl, null);
                    }
                }

                resultsCache.putMany(entriesToCache);
                componentReports.addAll(batchReports);
            }
        }

        final var vulnBuilderByVulnId = new HashMap<String, Vulnerability.Builder>();

        for (final var componentReport : componentReports) {
            for (final ComponentReportVulnerability reportedVuln : componentReport.vulnerabilities()) {
                final Vulnerability.Builder vulnBuilder =
                        vulnBuilderByVulnId.computeIfAbsent(
                                reportedVuln.id(),
                                ignored -> OssIndexModelConverter.convert(reportedVuln));

                final List<String> bomRefs = bomRefsByPurl.get(componentReport.coordinates());
                for (final String bomRef : bomRefs) {
                    vulnBuilder.addAffects(
                            VulnerabilityAffects.newBuilder()
                                    .setRef(bomRef)
                                    .build());
                }
            }
        }

        return Bom
                .newBuilder()
                .addAllVulnerabilities(
                        vulnBuilderByVulnId.values().stream()
                                .map(Vulnerability.Builder::build)
                                .toList())
                .build();
    }

    List<ComponentReport> getComponentReports(Collection<String> coordinates) throws IOException {
        if (coordinates.isEmpty()) {
            return List.of();
        }

        final var requestBody = new ComponentReportRequest(coordinates);
        final byte[] requestBytes = objectMapper.writeValueAsBytes(requestBody);

        final var requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl + "/api/v3/component-report"))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(BodyPublishers.ofByteArray(requestBytes));

        if (username != null && apiToken != null) {
            final String credentials = username + ":" + apiToken;
            final String encoded = Base64.getEncoder()
                    .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            requestBuilder.header("Authorization", "Basic " + encoded);
        }

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(requestBuilder.build(), BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Request interrupted", e);
        }

        try (final InputStream bodyInputStream = response.body()) {
            if (response.statusCode() == 200) {
                return objectMapper.readValue(bodyInputStream, new TypeReference<>() {
                });
            }

            throw new IOException("OSS Index API request failed with status " + response.statusCode());
        }
    }

    private static <T> List<List<T>> partition(List<T> list, int batchSize) {
        final var partitions = new ArrayList<List<T>>();
        for (int i = 0; i < list.size(); i += batchSize) {
            partitions.add(list.subList(i, Math.min(i + batchSize, list.size())));
        }

        return partitions;
    }

}
