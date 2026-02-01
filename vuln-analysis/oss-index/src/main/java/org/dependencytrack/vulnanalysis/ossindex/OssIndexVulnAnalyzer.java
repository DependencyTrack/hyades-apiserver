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
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

/**
 * @since 5.7.0
 */
final class OssIndexVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(OssIndexVulnAnalyzer.class);
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

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI apiUrl;
    private final String username;
    private final String apiToken;

    OssIndexVulnAnalyzer(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiUrl,
            String username,
            String apiToken) {
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

        // TODO: Check cache.

        final var componentReports = new ArrayList<ComponentReport>(bomRefsByPurl.size());

        final List<List<String>> purlPartitions = partition(List.copyOf(bomRefsByPurl.keySet()));
        for (final var purlPartition : purlPartitions) {
            try {
                componentReports.addAll(getComponentReports(purlPartition));
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to retrieve component report", e);
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

                // TODO: Add to cache.
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

    private static <T> List<List<T>> partition(List<T> list) {
        final var partitions = new ArrayList<List<T>>();
        for (int i = 0; i < list.size(); i += 128) {
            partitions.add(list.subList(i, Math.min(i + 128, list.size())));
        }

        return partitions;
    }

}
