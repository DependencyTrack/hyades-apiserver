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
package org.dependencytrack.workflow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.apache.commons.collections4.ListUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResultX;
import org.dependencytrack.storage.FileMetadata;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.annotation.Activity;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.Json;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@Activity(name = "ossindex-analysis")
public class OssIndexAnalysisActivity implements ActivityRunner<AnalyzeProjectArgs, AnalyzeProjectVulnsResultX> {

    private static final Logger LOGGER = LoggerFactory.getLogger(OssIndexAnalysisActivity.class);

    private final Source SOURCE_NVD = Source.newBuilder().setName("NVD").build();
    private final Source SOURCE_OSSINDEX = Source.newBuilder().setName("OSSINDEX").build();

    private final JsonMapper jsonMapper = new JsonMapper(); // TODO: Use a shared instance.
    private final Map<String, List<Vulnerability>> cache = new ConcurrentHashMap<>(); // TODO: Use a proper cache (javax.cache?).

    @Override
    public Optional<AnalyzeProjectVulnsResultX> run(final ActivityRunContext<AnalyzeProjectArgs> ctx) throws Exception {
        final AnalyzeProjectArgs args = ctx.argument().orElseThrow();
        final UUID projectUuid = UUID.fromString(args.getProject().getUuid());

        final Map<Long, String> purlByComponentId = getComponentPurls(projectUuid);
        if (purlByComponentId.isEmpty()) {
            return Optional.empty();
        }

        final Map<String, List<Long>> componentIdsByPurl = purlByComponentId.entrySet().stream()
                .collect(Collectors.groupingBy(
                        Map.Entry::getValue,
                        Collectors.mapping(Map.Entry::getKey, Collectors.toList())));

        final var vulnsByPurl = new HashMap<String, List<Vulnerability>>(purlByComponentId.size());
        for (final String purl : componentIdsByPurl.keySet()) {
            final List<Vulnerability> cachedVulns = cache.get(purl);
            if (cachedVulns != null) {
                vulnsByPurl.put(purl, cachedVulns);
            }
        }

        final List<String> purlsToSubmit = componentIdsByPurl.keySet().stream()
                .filter(purl -> !vulnsByPurl.containsKey(purl))
                .toList();

        final List<List<String>> purlPartitions = ListUtils.partition(purlsToSubmit, 128);
        for (final List<String> purlPartition : purlPartitions) {
            final var purlJsonArrayBuilder = Json.createArrayBuilder();
            purlPartition.forEach(purlJsonArrayBuilder::add);
            final var requestPayload = Json.createObjectBuilder()
                    .add("coordinates", purlJsonArrayBuilder)
                    .build();

            final var request = new HttpPost("https://ossindex.sonatype.org/api/v3/component-report");
            request.addHeader("Accept", "application/json");
            request.addHeader("Content-Type", "application/json");
            request.addHeader("User-Agent", ManagedHttpClientFactory.getUserAgent());
            request.setEntity(new StringEntity(requestPayload.toString()));

            // TODO: Add synchronous retries and circuit breakers.
            //  Blocking retries are cheap because we're running inside a virtual thread.
            //  When blocking retries are exceeded or circuit breaker is open,
            //  yield and let the workflow handle further retries.
            LOGGER.info("Submitting {} PURLs for analysis", purlPartition.size());
            final String responsePayload;
            try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                if (response.getStatusLine().getStatusCode() != 200) {
                    throw new IllegalStateException("Unexpected response code: " + response.getStatusLine().getStatusCode());
                }

                responsePayload = EntityUtils.toString(response.getEntity());
            }

            final Map<String, List<Vulnerability>> parsedVulnsByPurl = parseResponse(responsePayload);
            for (final Map.Entry<String, List<Vulnerability>> entry : parsedVulnsByPurl.entrySet()) {
                vulnsByPurl.put(entry.getKey(), entry.getValue());
                cache.putIfAbsent(entry.getKey(), entry.getValue());
            }
        }

        final var resultBuilder = AnalyzeProjectVulnsResult.newBuilder();
        for (final Map.Entry<String, List<Vulnerability>> entry : vulnsByPurl.entrySet()) {
            final String purl = entry.getKey();
            final List<Vulnerability> vulns = entry.getValue();

            final List<Long> componentIds = componentIdsByPurl.get(purl);
            if (componentIds == null) {
                LOGGER.warn("""
                        Received results for PURL {}, but no submitted component is associated with.\
                        PURLs of submitted components are: {}""", purl, purlsToSubmit);
                continue;
            }

            resultBuilder.addAllResults(componentIds.stream()
                    .map(componentId -> AnalyzeProjectVulnsResult.ComponentResult.newBuilder()
                            .setComponentId(componentId)
                            .addAllVulns(vulns)
                            .build())
                    .toList());
        }

        final FileMetadata resultFileMetadata;
        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            resultFileMetadata = fileStorage.store(
                    "ossindex-result", resultBuilder.build().toByteArray());
        }

        return Optional.of(AnalyzeProjectVulnsResultX.newBuilder()
                .setResultsFileMetadata(org.dependencytrack.proto.storage.v1alpha1.FileMetadata.newBuilder()
                        .setKey(resultFileMetadata.key())
                        .setSha256(resultFileMetadata.sha256())
                        .setStorage(resultFileMetadata.storage())
                        .build())
                .build());
    }

    private Map<Long, String> getComponentPurls(final UUID projectUuid) {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "COMPONENT"."ID"
                         , "COMPONENT"."PURL"
                      FROM "COMPONENT"
                     INNER JOIN "PROJECT"
                        ON "PROJECT"."ID" = "COMPONENT"."PROJECT_ID"
                     WHERE "PROJECT"."UUID" = :projectUuid
                       AND "COMPONENT"."PURL" IS NOT NULL
                    """);

            return query
                    .setMapKeyColumn("ID")
                    .setMapValueColumn("PURL")
                    .bind("projectUuid", projectUuid)
                    .collectInto(new GenericType<>() {
                    });
        });
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ComponentReport(
            String coordinates,
            String description,
            String reference,
            List<ComponentReportVulnerability> vulnerabilities) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ComponentReportVulnerability(
            String id,
            String displayName,
            String title,
            String description,
            Float cvssScore,
            String cvssVector,
            String cwe,
            String cve,
            String reference,
            List<String> externalReferences) {
    }

    private Map<String, List<Vulnerability>> parseResponse(final String response) throws IOException {
        final ObjectReader reportReader = jsonMapper.readerForListOf(ComponentReport.class);
        final List<ComponentReport> reports = reportReader.readValue(response);

        final var vulnsByPurl = new HashMap<String, List<Vulnerability>>();
        for (final var report : reports) {
            final String purl = report.coordinates();

            final List<ComponentReportVulnerability> reportVulns = report.vulnerabilities();
            if (reportVulns == null || reportVulns.isEmpty()) {
                vulnsByPurl.put(purl, Collections.emptyList());
                continue;
            }

            final var vulns = new ArrayList<Vulnerability>(reportVulns.size());
            for (final ComponentReportVulnerability reportVuln : reportVulns) {
                final var vulnBuilder = Vulnerability.newBuilder();
                vulnBuilder.setId(reportVuln.id());
                vulnBuilder.setSource(reportVuln.id().toLowerCase().startsWith("cve-")
                        ? SOURCE_NVD
                        : SOURCE_OSSINDEX);

                vulns.add(vulnBuilder.build());
            }

            vulnsByPurl.put(purl, vulns);
        }

        return vulnsByPurl;
    }

}