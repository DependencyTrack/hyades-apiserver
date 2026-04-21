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
package org.dependencytrack.vulnanalysis.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

final class OsvVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvVulnAnalyzer.class);
    private static final Source SOURCE_OSV = Source.newBuilder().setName("OSV").build();
    private static final int QUERY_CACHE_BATCH_SIZE = 1000;
    private static final int QUERY_BATCH_SIZE = 1000;

    private final Cache resultsCache;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI apiUrl;

    OsvVulnAnalyzer(
            Cache resultsCache,
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiUrl) {
        this.resultsCache = resultsCache;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.apiUrl = apiUrl;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        final Map<String, Set<String>> bomRefsByPurl = collectAnalyzablePurls(bom);
        if (bomRefsByPurl.isEmpty()) {
            LOGGER.debug("No analyzable PURLs found; Skipping analysis");
            return Bom.getDefaultInstance();
        }

        final Map<String, Set<String>> vulnIdsByPurl;
        try {
            vulnIdsByPurl = queryPurls(bomRefsByPurl.keySet());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        // TODO: Fetch vulnerability records: https://google.github.io/osv.dev/get-v1-vulns/

        return assembleVdr(vulnIdsByPurl, bomRefsByPurl);
    }

    private Map<String, Set<String>> collectAnalyzablePurls(Bom bom) {
        final var bomRefsByPurl = new LinkedHashMap<String, Set<String>>();

        for (final Component component : bom.getComponentsList()) {
            if (!component.hasBomRef() || !component.hasPurl()) {
                continue;
            }
            if (component.getPropertiesCount() > 0
                    && component.getPropertiesList().stream()
                    .map(Property::getName)
                    .anyMatch("dependencytrack:internal:is-internal-component"::equalsIgnoreCase)) {
                continue;
            }

            try {
                final var purl = new PackageURL(component.getPurl());
                if (purl.getVersion() == null) {
                    continue;
                }

                bomRefsByPurl
                        .computeIfAbsent(purl.canonicalize(), k -> new HashSet<>())
                        .add(component.getBomRef());
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Failed to parse PURL '{}'; Skipping", component.getPurl(), e);
            }
        }

        return bomRefsByPurl;
    }

    private Map<String, Set<String>> queryPurls(Collection<String> purls) throws IOException, InterruptedException {
        final var cachedVulnIdsByPurl = new HashMap<String, Set<String>>();
        for (final var purlBatch : partition(List.copyOf(purls), QUERY_CACHE_BATCH_SIZE)) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all cache lookups could complete");
            }

            final Map<String, byte[]> cachedBytesByPurl = resultsCache.getMany(Set.copyOf(purlBatch));
            LOGGER.debug("Found cached results for {}/{} PURLs", cachedBytesByPurl.size(), purlBatch.size());

            for (final var entry : cachedBytesByPurl.entrySet()) {
                final String purl = entry.getKey();
                final byte[] cachedBytes = entry.getValue();

                if (cachedBytes == null) {
                    cachedVulnIdsByPurl.put(purl, Set.of());
                    continue;
                }

                try {
                    final var vulnIds = objectMapper.readValue(cachedBytes, String[].class);
                    cachedVulnIdsByPurl.put(purl, Set.of(vulnIds));
                } catch (IOException e) {
                    LOGGER.warn("Failed to deserialize cached component report for PURL '{}'; Will re-fetch", purl, e);
                }
            }
        }

        final var queryQueue = new LinkedBlockingQueue<>(
                purls.stream()
                        .filter(purl -> !cachedVulnIdsByPurl.containsKey(purl))
                        .map(QueryBatchRequest.Query::new)
                        .toList());

        final var vulnIdsByPurl = new HashMap<String, Set<String>>(purls.size());
        final var batch = new ArrayList<QueryBatchRequest.Query>(Math.min(queryQueue.size(), QUERY_BATCH_SIZE));

        while (!queryQueue.isEmpty()) {
            queryQueue.drainTo(batch, QUERY_BATCH_SIZE);

            final QueryBatchResponse response = queryBatch(new QueryBatchRequest(batch));
            for (int i = 0; i < batch.size(); i++) {
                final QueryBatchRequest.Query query = batch.get(i);
                final QueryBatchResponse.Result result = response.results().get(i);

                final List<QueryBatchResponse.Vuln> vulns = response.results().get(i).vulns();
                if (vulns != null && !vulns.isEmpty()) {
                    vulnIdsByPurl
                            .computeIfAbsent(query.pkg().purl(), k -> new HashSet<>())
                            .addAll(vulns.stream().map(QueryBatchResponse.Vuln::id).toList());
                } else {
                    vulnIdsByPurl.putIfAbsent(query.pkg().purl(), Set.of());
                }

                if (result.nextPageToken() != null) {
                    queryQueue.add(new QueryBatchRequest.Query(query.pkg(), result.nextPageToken()));
                }
            }

            batch.clear();
        }

        final var entriesToCache = new HashMap<String, byte @Nullable []>(vulnIdsByPurl.size());
        for (var entry : vulnIdsByPurl.entrySet()) {
            final String purl = entry.getKey();
            final Set<String> vulnIds = entry.getValue();

            entriesToCache.put(
                    purl,
                    !vulnIds.isEmpty()
                            ? objectMapper.writeValueAsBytes(vulnIds)
                            : null);
        }
        resultsCache.putMany(entriesToCache);

        vulnIdsByPurl.putAll(cachedVulnIdsByPurl);
        return vulnIdsByPurl;
    }

    private QueryBatchResponse queryBatch(QueryBatchRequest request) throws IOException, InterruptedException {
        final byte[] serializedRequest;
        try {
            serializedRequest = objectMapper.writeValueAsBytes(request);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final var httpRequest = HttpRequest.newBuilder()
                .uri(apiUrl.resolve("/v1/querybatch"))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofByteArray(serializedRequest))
                .build();

        final HttpResponse<String> response = httpClient.send(
                httpRequest, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return objectMapper.readValue(response.body(), QueryBatchResponse.class);
        }

        throw new IOException("OSV API request failed with status " + response.statusCode());
    }

    private Bom assembleVdr(
            Map<String, Set<String>> vulnIdsByPurl,
            Map<String, Set<String>> bomRefsByPurl) {
        final var vulnBuilderByVulnId = new HashMap<String, Vulnerability.Builder>();

        for (final var entry : vulnIdsByPurl.entrySet()) {
            final String purl = entry.getKey();
            final Set<String> vulnIds = entry.getValue();

            final Set<String> bomRefs = bomRefsByPurl.get(purl);
            if (bomRefs == null) {
                LOGGER.warn("""
                        Received vulnerabilities for PURL '{}', but no component \
                        with this PURL was submitted for analysis""", purl);
                continue;
            }

            for (final var vulnId : vulnIds) {
                final Vulnerability.Builder vulnBuilder =
                        vulnBuilderByVulnId.computeIfAbsent(
                                vulnId,
                                ignored -> Vulnerability.newBuilder().setId(vulnId).setSource(SOURCE_OSV));

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

    private static <T> List<List<T>> partition(List<T> list, int batchSize) {
        final var partitions = new ArrayList<List<T>>();
        for (int i = 0; i < list.size(); i += batchSize) {
            partitions.add(list.subList(i, Math.min(i + batchSize, list.size())));
        }

        return partitions;
    }

}
