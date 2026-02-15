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
package org.dependencytrack.vulnanalysis;

import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.model.VulnIdAndSource;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.plugin.NoSuchExtensionException;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyEvaluator;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg.AnalyzerResult;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;
import static org.dependencytrack.notification.api.NotificationFactory.createNewVulnerabilityNotification;
import static org.dependencytrack.parser.dependencytrack.BovModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@ActivitySpec(name = "reconcile-vuln-analysis-results")
public final class ReconcileVulnAnalysisResultsActivity implements Activity<ReconcileVulnAnalysisResultsArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReconcileVulnAnalysisResultsActivity.class);

    private static final String INTERNAL_VULN_ID_PROPERTY = "dependencytrack:internal:vulnerability-id";

    private final PluginManager pluginManager;
    private final VulnerabilityPolicyEvaluator vulnPolicyEvaluator;

    public ReconcileVulnAnalysisResultsActivity(
            PluginManager pluginManager,
            VulnerabilityPolicyEvaluator vulnPolicyEvaluator) {
        this.pluginManager = pluginManager;
        this.vulnPolicyEvaluator = vulnPolicyEvaluator;
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable ReconcileVulnAnalysisResultsArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final var projectUuid = UUID.fromString(arg.getProjectUuid());

        try (var ignored = MDC.putCloseable(MDC_PROJECT_UUID, projectUuid.toString())) {
            LOGGER.info(
                    "Reconciling results from {} vulnerability analyzers",
                    arg.getAnalyzerResultsCount());

            final var failedAnalyzers = new HashSet<String>();
            final var reportedFindings = new ArrayList<ReportedFinding>();
            final var vulnDetailsByKey = new HashMap<VulnIdAndSource, ReportedVulnerability>();

            for (final AnalyzerResult result : arg.getAnalyzerResultsList()) {
                final String analyzerName = result.getAnalyzerName();
                try (var ignoredMdcAnalyzerName = MDC.putCloseable(MDC_VULN_ANALYZER_NAME, analyzerName)) {
                    LOGGER.debug("Processing analyzer results");

                    if (!result.getSuccessful()) {
                        LOGGER.debug("Analyzer failed");
                        failedAnalyzers.add(analyzerName);
                        continue;
                    }

                    if (!result.hasVdrFileMetadata()) {
                        LOGGER.debug("Analyzer did not produce any results");
                        continue;
                    }

                    final Bom vdr;
                    try (final var fileStorage = pluginManager.getExtension(
                            FileStorage.class, result.getVdrFileMetadata().getProviderName());
                         final InputStream vdrInputStream = fileStorage.get(result.getVdrFileMetadata())) {
                        vdr = Bom.parseFrom(vdrInputStream);
                    } catch (FileNotFoundException e) {
                        LOGGER.warn("Could not find VDR file from analyzer; Considering it to have failed", e);
                        failedAnalyzers.add(analyzerName);
                        continue;
                    }

                    collectFindingsFromVdr(analyzerName, vdr, reportedFindings, vulnDetailsByKey);
                }
            }

            if (arg.getAnalyzerResultsCount() == failedAnalyzers.size()) {
                LOGGER.warn("No successful analyzers; skipping reconciliation");
                return null;
            }

            LOGGER.debug(
                    "Extracted {} findings and {} unique vulnerabilities from VDRs",
                    reportedFindings.size(),
                    vulnDetailsByKey.size());

            final Map<VulnIdAndSource, ConvertedVulnerability> convertedVulns = convertVulns(vulnDetailsByKey);
            LOGGER.debug("Converted {} vulnerabilities", convertedVulns.size());

            LOGGER.debug("Synchronizing {} vulnerabilities", convertedVulns.size());
            final Map<VulnIdAndSource, Long> vulnDbIdByVulnIdAndSource = syncVulns(convertedVulns);
            LOGGER.debug("Synchronized {} vulnerabilities", vulnDbIdByVulnIdAndSource.size());

            reconcileFindings(
                    projectUuid,
                    reportedFindings,
                    vulnDbIdByVulnIdAndSource,
                    failedAnalyzers);
        }

        return null;
    }

    private static void collectFindingsFromVdr(
            String analyzerName,
            Bom vdr,
            List<ReportedFinding> findings,
            Map<VulnIdAndSource, ReportedVulnerability> vulnDetails) {
        for (final Vulnerability vdrVuln : vdr.getVulnerabilitiesList()) {
            final org.dependencytrack.model.Vulnerability.Source source =
                    BovModelConverter.extractSource(vdrVuln.getId(), vdrVuln.getSource());
            final var vulnIdAndSource = new VulnIdAndSource(vdrVuln.getId(), source);

            final Long internalVulnId = extractInternalVulnId(vdrVuln);

            vulnDetails.merge(vulnIdAndSource,
                    new ReportedVulnerability(vdrVuln, analyzerName, internalVulnId),
                    (existing, incoming) -> {
                        if (existing.internalVulnId() != null) {
                            return existing;
                        }
                        if (incoming.internalVulnId() != null) {
                            return incoming;
                        }

                        final int existingPriority = getSourcePriority(existing.vdrVuln().getSource().getName());
                        final int incomingPriority = getSourcePriority(incoming.vdrVuln().getSource().getName());

                        return existingPriority <= incomingPriority ? existing : incoming;
                    });

            for (final VulnerabilityAffects affects : vdrVuln.getAffectsList()) {
                try {
                    final long componentId = Long.parseLong(affects.getRef());
                    findings.add(new ReportedFinding(componentId, vulnIdAndSource, analyzerName));
                } catch (NumberFormatException e) {
                    LOGGER.warn(
                            "Encountered invalid BOM ref '{}' for vulnerability '{}'",
                            affects.getRef(),
                            vulnIdAndSource,
                            e);
                }
            }
        }
    }

    private static @Nullable Long extractInternalVulnId(Vulnerability vuln) {
        for (final Property prop : vuln.getPropertiesList()) {
            if (INTERNAL_VULN_ID_PROPERTY.equals(prop.getName())) {
                try {
                    return Long.parseLong(prop.getValue());
                } catch (NumberFormatException e) {
                    LOGGER.warn("Invalid internal vulnerability ID: {}", prop.getValue());
                }
            }
        }

        return null;
    }

    private static int getSourcePriority(String source) {
        return switch (source.toUpperCase()) {
            case "NVD" -> 0;
            case "GITHUB" -> 1;
            case "OSV" -> 2;
            case "OSSINDEX" -> 3;
            case "SNYK" -> 4;
            default -> 99;
        };
    }

    private Map<VulnIdAndSource, ConvertedVulnerability> convertVulns(
            Map<VulnIdAndSource, ReportedVulnerability> detailsByVulnIdAndSource) {
        if (detailsByVulnIdAndSource.isEmpty()) {
            return Map.of();
        }

        final var converted = new HashMap<VulnIdAndSource, ConvertedVulnerability>();

        for (final var entry : detailsByVulnIdAndSource.entrySet()) {
            final VulnIdAndSource vulnIdAndSource = entry.getKey();
            final ReportedVulnerability extracted = entry.getValue();

            if (extracted.internalVulnId() != null) {
                converted.put(vulnIdAndSource, new ConvertedVulnerability(
                        null, extracted.analyzerName(), extracted.internalVulnId()));
                continue;
            }

            try {
                final Bom miniBom = Bom.newBuilder()
                        .addVulnerabilities(extracted.vdrVuln())
                        .build();
                final org.dependencytrack.model.Vulnerability vuln = convert(miniBom, extracted.vdrVuln(), true);
                converted.put(vulnIdAndSource, new ConvertedVulnerability(vuln, extracted.analyzerName(), null));
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to convert vulnerability {}: {}", vulnIdAndSource, e.getMessage());
            }
        }

        return converted;
    }

    private Map<VulnIdAndSource, Long> syncVulns(
            Map<VulnIdAndSource, ConvertedVulnerability> convertedVulnByVulnIdAndSource) {
        if (convertedVulnByVulnIdAndSource.size() <= 100) {
            return syncVulnsBatch(convertedVulnByVulnIdAndSource);
        }

        final var syncedVulns = new HashMap<VulnIdAndSource, Long>(convertedVulnByVulnIdAndSource.size());

        final var batch = new HashMap<VulnIdAndSource, ConvertedVulnerability>(100);
        for (final var entry : convertedVulnByVulnIdAndSource.entrySet()) {
            final VulnIdAndSource vulnIdAndSource = entry.getKey();
            final ConvertedVulnerability convertedVuln = entry.getValue();

            batch.put(vulnIdAndSource, convertedVuln);
            if (batch.size() >= 100) {
                syncedVulns.putAll(syncVulnsBatch(batch));
                batch.clear();
            }
        }
        if (!batch.isEmpty()) {
            syncedVulns.putAll(syncVulnsBatch(batch));
        }

        return syncedVulns;
    }

    private Map<VulnIdAndSource, Long> syncVulnsBatch(
            Map<VulnIdAndSource, ConvertedVulnerability> convertedVulnByVulnIdAndSource) {
        if (convertedVulnByVulnIdAndSource.isEmpty()) {
            return Map.of();
        }

        LOGGER.debug("Synchronizing batch of {} vulnerabilities", convertedVulnByVulnIdAndSource.size());

        final var results = new HashMap<VulnIdAndSource, Long>(convertedVulnByVulnIdAndSource.size());

        // If all vulnerabilities are internal, we don't need to sync anything
        // and can simply short-circuit here, without performing any SQL queries.
        for (final var entry : convertedVulnByVulnIdAndSource.entrySet()) {
            if (entry.getValue().internalVulnId() != null) {
                results.put(entry.getKey(), entry.getValue().internalVulnId());
            }
        }
        if (results.size() == convertedVulnByVulnIdAndSource.size()) {
            return results;
        }

        final int vulnsToSyncCount = convertedVulnByVulnIdAndSource.size() - results.size();
        final var vulnIds = new String[vulnsToSyncCount];
        final var sources = new String[vulnsToSyncCount];
        final var friendlyVulnIds = new String[vulnsToSyncCount];
        final var titles = new String[vulnsToSyncCount];
        final var subTitles = new String[vulnsToSyncCount];
        final var descriptions = new String[vulnsToSyncCount];
        final var details = new String[vulnsToSyncCount];
        final var recommendations = new String[vulnsToSyncCount];
        final var references = new String[vulnsToSyncCount];
        final var credits = new String[vulnsToSyncCount];
        final var createdArray = new Date[vulnsToSyncCount];
        final var publishedArray = new Date[vulnsToSyncCount];
        final var updatedArray = new Date[vulnsToSyncCount];
        final var cwesArray = new String[vulnsToSyncCount];
        final var cvssV2BaseScores = new Double[vulnsToSyncCount];
        final var cvssV2ImpactSubScores = new Double[vulnsToSyncCount];
        final var cvssV2ExploitabilitySubScores = new Double[vulnsToSyncCount];
        final var cvssV2Vectors = new String[vulnsToSyncCount];
        final var cvssV3BaseScores = new Double[vulnsToSyncCount];
        final var cvssV3ImpactSubScores = new Double[vulnsToSyncCount];
        final var cvssV3ExploitabilitySubScores = new Double[vulnsToSyncCount];
        final var cvssV3Vectors = new String[vulnsToSyncCount];
        final var owaspRRLikelihoodScores = new Double[vulnsToSyncCount];
        final var owaspRRTechnicalImpactScores = new Double[vulnsToSyncCount];
        final var owaspRRBusinessImpactScores = new Double[vulnsToSyncCount];
        final var owaspRRVectors = new String[vulnsToSyncCount];
        final var severities = new String[vulnsToSyncCount];
        final var vulnerableVersions = new String[vulnsToSyncCount];
        final var patchedVersions = new String[vulnsToSyncCount];
        final var canUpdateArray = new boolean[vulnsToSyncCount];

        // Determining whether a vulnerability is updatable requires
        // checking for which vulnerability sources mirroring is enabled.
        // To prevent excessive checks that all come to the same conclusion,
        // maintain a local cache of check results.
        final var canUpdateCache = new HashMap<Map.Entry<org.dependencytrack.model.Vulnerability.Source, String>, Boolean>();

        int i = 0;
        for (final var entry : convertedVulnByVulnIdAndSource.entrySet()) {
            if (entry.getValue().internalVulnId() != null) {
                // Internal vulnerabilities have already been dealt with.
                continue;
            }

            final org.dependencytrack.model.Vulnerability vuln = entry.getValue().vuln();
            vulnIds[i] = vuln.getVulnId();
            sources[i] = vuln.getSource();
            friendlyVulnIds[i] = vuln.getFriendlyVulnId();
            titles[i] = vuln.getTitle();
            subTitles[i] = vuln.getSubTitle();
            descriptions[i] = vuln.getDescription();
            details[i] = vuln.getDetail();
            recommendations[i] = vuln.getRecommendation();
            references[i] = vuln.getReferences();
            credits[i] = vuln.getCredits();
            createdArray[i] = vuln.getCreated();
            publishedArray[i] = vuln.getPublished();
            updatedArray[i] = vuln.getUpdated();
            cwesArray[i] = (vuln.getCwes() != null && !vuln.getCwes().isEmpty())
                    ? vuln.getCwes().stream().map(String::valueOf).collect(Collectors.joining(","))
                    : null;
            cvssV2BaseScores[i] = vuln.getCvssV2BaseScore() != null
                    ? vuln.getCvssV2BaseScore().doubleValue()
                    : null;
            cvssV2ImpactSubScores[i] = vuln.getCvssV2ImpactSubScore() != null
                    ? vuln.getCvssV2ImpactSubScore().doubleValue()
                    : null;
            cvssV2ExploitabilitySubScores[i] = vuln.getCvssV2ExploitabilitySubScore() != null
                    ? vuln.getCvssV2ExploitabilitySubScore().doubleValue()
                    : null;
            cvssV2Vectors[i] = vuln.getCvssV2Vector();
            cvssV3BaseScores[i] = vuln.getCvssV3BaseScore() != null
                    ? vuln.getCvssV3BaseScore().doubleValue()
                    : null;
            cvssV3ImpactSubScores[i] = vuln.getCvssV3ImpactSubScore() != null
                    ? vuln.getCvssV3ImpactSubScore().doubleValue()
                    : null;
            cvssV3ExploitabilitySubScores[i] = vuln.getCvssV3ExploitabilitySubScore() != null
                    ? vuln.getCvssV3ExploitabilitySubScore().doubleValue()
                    : null;
            cvssV3Vectors[i] = vuln.getCvssV3Vector();
            owaspRRLikelihoodScores[i] = vuln.getOwaspRRLikelihoodScore() != null
                    ? vuln.getOwaspRRLikelihoodScore().doubleValue()
                    : null;
            owaspRRTechnicalImpactScores[i] = vuln.getOwaspRRTechnicalImpactScore() != null
                    ? vuln.getOwaspRRTechnicalImpactScore().doubleValue()
                    : null;
            owaspRRBusinessImpactScores[i] = vuln.getOwaspRRBusinessImpactScore() != null
                    ? vuln.getOwaspRRBusinessImpactScore().doubleValue()
                    : null;
            owaspRRVectors[i] = vuln.getOwaspRRVector();
            severities[i] = vuln.getSeverity() != null
                    ? vuln.getSeverity().name()
                    : null;
            vulnerableVersions[i] = vuln.getVulnerableVersions();
            patchedVersions[i] = vuln.getPatchedVersions();
            canUpdateArray[i] = canUpdateCache.computeIfAbsent(
                    Map.entry(
                            org.dependencytrack.model.Vulnerability.Source.valueOf(vuln.getSource()),
                            entry.getValue().analyzerName()),
                    k -> canUpdateVulnerability(k.getKey(), k.getValue()));
            i++;
        }

        // NB: The SQL statement is huge, but it avoids a multitude of potential
        // concurrency issues that would overwise require (optimistic) locking and retries,
        // while simultaneously being significantly more efficient than doing all of it in-memory.
        useJdbiTransaction(handle -> {
            final Query query = handle.createQuery("""
                    WITH
                    cte_input AS (
                      SELECT vuln_id
                           , source
                           , friendly_vuln_id
                           , title
                           , sub_title
                           , description
                           , detail
                           , recommendation
                           , "references"
                           , credits
                           , created
                           , published
                           , updated
                           , cwes
                           , cvss_v2_base_score
                           , cvss_v2_impact_sub_score
                           , cvss_v2_exploitability_sub_score
                           , cvss_v2_vector
                           , cvss_v3_base_score
                           , cvss_v3_impact_sub_score
                           , cvss_v3_exploitability_sub_score
                           , cvss_v3_vector
                           , owasp_rr_likelihood_score
                           , owasp_rr_technical_impact_score
                           , owasp_rr_business_impact_score
                           , owasp_rr_vector
                           , "severity"
                           , vulnerable_versions
                           , patched_versions
                           , can_update
                        FROM UNNEST (
                          :vulnIds
                        , :sources
                        , :friendlyVulnIds
                        , :titles
                        , :subTitles
                        , :descriptions
                        , :details
                        , :recommendations
                        , :references
                        , :credits
                        , :createdArray
                        , :publishedArray
                        , :updatedArray
                        , :cwesArray
                        , :cvssV2BaseScores
                        , :cvssV2ImpactSubScores
                        , :cvssV2ExploitabilitySubScores
                        , :cvssV2Vectors
                        , :cvssV3BaseScores
                        , :cvssV3ImpactSubScores
                        , :cvssV3ExploitabilitySubScores
                        , :cvssV3Vectors
                        , :owaspRRLikelihoodScores
                        , :owaspRRTechnicalImpactScores
                        , :owaspRRBusinessImpactScores
                        , :owaspRRVectors
                        , :severities
                        , :vulnerableVersions
                        , :patchedVersions
                        , :canUpdateArray
                        ) AS t (
                          vuln_id
                        , source
                        , friendly_vuln_id
                        , title
                        , sub_title
                        , description
                        , detail
                        , recommendation
                        , "references"
                        , credits
                        , created
                        , published
                        , updated
                        , cwes
                        , cvss_v2_base_score
                        , cvss_v2_impact_sub_score
                        , cvss_v2_exploitability_sub_score
                        , cvss_v2_vector
                        , cvss_v3_base_score
                        , cvss_v3_impact_sub_score
                        , cvss_v3_exploitability_sub_score
                        , cvss_v3_vector
                        , owasp_rr_likelihood_score
                        , owasp_rr_technical_impact_score
                        , owasp_rr_business_impact_score
                        , owasp_rr_vector
                        , "severity"
                        , vulnerable_versions
                        , patched_versions
                        , can_update
                        )
                    ),
                    cte_modified AS (
                      INSERT INTO "VULNERABILITY" AS v (
                        "VULNID"
                      , "SOURCE"
                      , "FRIENDLYVULNID"
                      , "TITLE"
                      , "SUBTITLE"
                      , "DESCRIPTION"
                      , "DETAIL"
                      , "RECOMMENDATION"
                      , "REFERENCES"
                      , "CREDITS"
                      , "CREATED"
                      , "PUBLISHED"
                      , "UPDATED"
                      , "CWES"
                      , "CVSSV2BASESCORE"
                      , "CVSSV2IMPACTSCORE"
                      , "CVSSV2EXPLOITSCORE"
                      , "CVSSV2VECTOR"
                      , "CVSSV3BASESCORE"
                      , "CVSSV3IMPACTSCORE"
                      , "CVSSV3EXPLOITSCORE"
                      , "CVSSV3VECTOR"
                      , "OWASPRRLIKELIHOODSCORE"
                      , "OWASPRRTECHNICALIMPACTSCORE"
                      , "OWASPRRBUSINESSIMPACTSCORE"
                      , "OWASPRRVECTOR"
                      , "SEVERITY"
                      , "VULNERABLEVERSIONS"
                      , "PATCHEDVERSIONS"
                      , "UUID"
                      )
                      SELECT vuln_id
                           , source
                           , friendly_vuln_id
                           , title
                           , sub_title
                           , description
                           , detail
                           , recommendation
                           , "references"
                           , credits
                           , created
                           , published
                           , updated
                           , cwes
                           , cvss_v2_base_score
                           , cvss_v2_impact_sub_score
                           , cvss_v2_exploitability_sub_score
                           , cvss_v2_vector
                           , cvss_v3_base_score
                           , cvss_v3_impact_sub_score
                           , cvss_v3_exploitability_sub_score
                           , cvss_v3_vector
                           , owasp_rr_likelihood_score
                           , owasp_rr_technical_impact_score
                           , owasp_rr_business_impact_score
                           , owasp_rr_vector
                           , CAST("severity" AS severity)
                           , vulnerable_versions
                           , patched_versions
                           , GEN_RANDOM_UUID()
                        FROM cte_input
                       ORDER BY vuln_id
                              , source
                      ON CONFLICT ("VULNID", "SOURCE") DO UPDATE
                      SET "FRIENDLYVULNID" = EXCLUDED."FRIENDLYVULNID"
                        , "TITLE" = EXCLUDED."TITLE"
                        , "SUBTITLE" = EXCLUDED."SUBTITLE"
                        , "DESCRIPTION" = EXCLUDED."DESCRIPTION"
                        , "DETAIL" = EXCLUDED."DETAIL"
                        , "RECOMMENDATION" = EXCLUDED."RECOMMENDATION"
                        , "REFERENCES" = EXCLUDED."REFERENCES"
                        , "CREDITS" = EXCLUDED."CREDITS"
                        , "CREATED" = EXCLUDED."CREATED"
                        , "PUBLISHED" = EXCLUDED."PUBLISHED"
                        , "UPDATED" = EXCLUDED."UPDATED"
                        , "CWES" = EXCLUDED."CWES"
                        , "CVSSV2BASESCORE" = EXCLUDED."CVSSV2BASESCORE"
                        , "CVSSV2IMPACTSCORE" = EXCLUDED."CVSSV2IMPACTSCORE"
                        , "CVSSV2EXPLOITSCORE" = EXCLUDED."CVSSV2EXPLOITSCORE"
                        , "CVSSV2VECTOR" = EXCLUDED."CVSSV2VECTOR"
                        , "CVSSV3BASESCORE" = EXCLUDED."CVSSV3BASESCORE"
                        , "CVSSV3IMPACTSCORE" = EXCLUDED."CVSSV3IMPACTSCORE"
                        , "CVSSV3EXPLOITSCORE" = EXCLUDED."CVSSV3EXPLOITSCORE"
                        , "CVSSV3VECTOR" = EXCLUDED."CVSSV3VECTOR"
                        , "OWASPRRLIKELIHOODSCORE" = EXCLUDED."OWASPRRLIKELIHOODSCORE"
                        , "OWASPRRTECHNICALIMPACTSCORE" = EXCLUDED."OWASPRRTECHNICALIMPACTSCORE"
                        , "OWASPRRBUSINESSIMPACTSCORE" = EXCLUDED."OWASPRRBUSINESSIMPACTSCORE"
                        , "OWASPRRVECTOR" = EXCLUDED."OWASPRRVECTOR"
                        , "SEVERITY" = EXCLUDED."SEVERITY"
                        , "VULNERABLEVERSIONS" = EXCLUDED."VULNERABLEVERSIONS"
                        , "PATCHEDVERSIONS" = EXCLUDED."PATCHEDVERSIONS"
                      WHERE TRUE
                        -- Only update when allowed to.
                        AND EXISTS (
                              SELECT 1
                                FROM cte_input AS i
                               WHERE i.vuln_id = v."VULNID"
                                 AND i.source = v."SOURCE"
                                 AND i.can_update
                            )
                        -- Only update when the incoming data is not older than the existing data.
                        AND (v."UPDATED" IS NULL OR EXCLUDED."UPDATED" > v."UPDATED")
                        -- Only update when any relevant field changed.
                        AND (
                              v."FRIENDLYVULNID"
                            , v."TITLE"
                            , v."SUBTITLE"
                            , v."DESCRIPTION"
                            , v."DETAIL"
                            , v."RECOMMENDATION"
                            , v."REFERENCES"
                            , v."CREDITS"
                            , v."CREATED"
                            , v."PUBLISHED"
                            , v."UPDATED"
                            , v."CWES"
                            , v."CVSSV2BASESCORE"
                            , v."CVSSV2IMPACTSCORE"
                            , v."CVSSV2EXPLOITSCORE"
                            , v."CVSSV2VECTOR"
                            , v."CVSSV3BASESCORE"
                            , v."CVSSV3IMPACTSCORE"
                            , v."CVSSV3EXPLOITSCORE"
                            , v."CVSSV3VECTOR"
                            , v."OWASPRRLIKELIHOODSCORE"
                            , v."OWASPRRTECHNICALIMPACTSCORE"
                            , v."OWASPRRBUSINESSIMPACTSCORE"
                            , v."OWASPRRVECTOR"
                            , v."SEVERITY"
                            , v."VULNERABLEVERSIONS"
                            , v."PATCHEDVERSIONS"
                            ) IS DISTINCT FROM (
                              EXCLUDED."FRIENDLYVULNID"
                            , EXCLUDED."TITLE"
                            , EXCLUDED."SUBTITLE"
                            , EXCLUDED."DESCRIPTION"
                            , EXCLUDED."DETAIL"
                            , EXCLUDED."RECOMMENDATION"
                            , EXCLUDED."REFERENCES"
                            , EXCLUDED."CREDITS"
                            , EXCLUDED."CREATED"
                            , EXCLUDED."PUBLISHED"
                            , EXCLUDED."UPDATED"
                            , EXCLUDED."CWES"
                            , EXCLUDED."CVSSV2BASESCORE"
                            , EXCLUDED."CVSSV2IMPACTSCORE"
                            , EXCLUDED."CVSSV2EXPLOITSCORE"
                            , EXCLUDED."CVSSV2VECTOR"
                            , EXCLUDED."CVSSV3BASESCORE"
                            , EXCLUDED."CVSSV3IMPACTSCORE"
                            , EXCLUDED."CVSSV3EXPLOITSCORE"
                            , EXCLUDED."CVSSV3VECTOR"
                            , EXCLUDED."OWASPRRLIKELIHOODSCORE"
                            , EXCLUDED."OWASPRRTECHNICALIMPACTSCORE"
                            , EXCLUDED."OWASPRRBUSINESSIMPACTSCORE"
                            , EXCLUDED."OWASPRRVECTOR"
                            , EXCLUDED."SEVERITY"
                            , EXCLUDED."VULNERABLEVERSIONS"
                            , EXCLUDED."PATCHEDVERSIONS"
                            )
                      RETURNING "VULNID"
                              , "SOURCE"
                              , "ID"
                    )
                    SELECT "VULNID"
                         , "SOURCE"
                         , "ID"
                      FROM cte_modified
                     UNION ALL
                    SELECT v."VULNID"
                         , v."SOURCE"
                         , v."ID"
                      FROM "VULNERABILITY" AS v
                     INNER JOIN cte_input AS i
                        ON i.vuln_id = v."VULNID"
                       AND i.source = v."SOURCE"
                     WHERE NOT EXISTS (
                                 SELECT 1
                                   FROM cte_modified AS m
                                  WHERE m."VULNID" = i.vuln_id
                                    AND m."SOURCE" = i.source
                               )
                    """);

            query
                    .bind("vulnIds", vulnIds)
                    .bind("sources", sources)
                    .bind("friendlyVulnIds", friendlyVulnIds)
                    .bind("titles", titles)
                    .bind("subTitles", subTitles)
                    .bind("descriptions", descriptions)
                    .bind("details", details)
                    .bind("recommendations", recommendations)
                    .bind("references", references)
                    .bind("credits", credits)
                    .bind("createdArray", createdArray)
                    .bind("publishedArray", publishedArray)
                    .bind("updatedArray", updatedArray)
                    .bind("cwesArray", cwesArray)
                    .bind("cvssV2BaseScores", cvssV2BaseScores)
                    .bind("cvssV2ImpactSubScores", cvssV2ImpactSubScores)
                    .bind("cvssV2ExploitabilitySubScores", cvssV2ExploitabilitySubScores)
                    .bind("cvssV2Vectors", cvssV2Vectors)
                    .bind("cvssV3BaseScores", cvssV3BaseScores)
                    .bind("cvssV3ImpactSubScores", cvssV3ImpactSubScores)
                    .bind("cvssV3ExploitabilitySubScores", cvssV3ExploitabilitySubScores)
                    .bind("cvssV3Vectors", cvssV3Vectors)
                    .bind("owaspRRLikelihoodScores", owaspRRLikelihoodScores)
                    .bind("owaspRRTechnicalImpactScores", owaspRRTechnicalImpactScores)
                    .bind("owaspRRBusinessImpactScores", owaspRRBusinessImpactScores)
                    .bind("owaspRRVectors", owaspRRVectors)
                    .bind("severities", severities)
                    .bind("vulnerableVersions", vulnerableVersions)
                    .bind("patchedVersions", patchedVersions)
                    .bind("canUpdateArray", canUpdateArray)
                    .map((rs, ctx) -> Map.entry(
                            new VulnIdAndSource(rs.getString("VULNID"), rs.getString("SOURCE")),
                            rs.getLong("ID")))
                    .stream()
                    .forEach(entry -> results.put(entry.getKey(), entry.getValue()));
        });

        return results;
    }

    private void reconcileFindings(
            UUID projectUuid,
            List<ReportedFinding> reportedFindings,
            Map<VulnIdAndSource, Long> vulnDbIdByVulnIdAndSource,
            Set<String> failedAnalyzers) {
        final Long projectId = withJdbiHandle(
                handle -> handle.attach(ProjectDao.class).getProjectId(projectUuid));
        if (projectId == null) {
            throw new TerminalApplicationFailureException("Project does not exist");
        }

        final List<FindingAttribution> existingFindingAttributions =
                withJdbiHandle(handle -> getExistingFindingAttributions(handle, projectId));
        final Map<FindingKey, List<FindingAttribution>> existingFindingByKey =
                existingFindingAttributions.stream()
                        .collect(Collectors.groupingBy(FindingKey::of));

        LOGGER.debug(
                "Found {} existing finding attribution(s) and {} unique finding(s)",
                existingFindingAttributions.size(),
                existingFindingByKey.size());

        // Determine which findings and finding attributions need to be created.
        final var createFindingCommands = new HashSet<CreateFindingCommand>();
        final var createFindingAttributionCommands = new HashSet<CreateFindingAttributionCommand>();

        for (final ReportedFinding reportedFinding : reportedFindings) {
            final Long vulnDbId = vulnDbIdByVulnIdAndSource.get(reportedFinding.vulnIdAndSource());
            if (vulnDbId == null) {
                LOGGER.warn("Vulnerability {} not found in database; Skipping", reportedFinding.vulnIdAndSource());
                continue;
            }

            final var findingKey = new FindingKey(reportedFinding.componentId(), vulnDbId);
            final List<FindingAttribution> existingFindingAttributionsForKey = existingFindingByKey.get(findingKey);

            final boolean findingExists = existingFindingAttributionsForKey != null
                    && !existingFindingAttributionsForKey.isEmpty();
            final boolean hasAttribution = existingFindingAttributionsForKey != null
                    && existingFindingAttributionsForKey.stream()
                    .anyMatch(ef -> ef.analyzerName().equals(reportedFinding.analyzerName()));

            if (!findingExists) {
                createFindingCommands.add(new CreateFindingCommand(findingKey));
            }

            if (!hasAttribution) {
                createFindingAttributionCommands.add(
                        new CreateFindingAttributionCommand(
                                vulnDbId,
                                reportedFinding.componentId(),
                                projectId,
                                reportedFinding.analyzerName()));
            }
        }

        // Determine which findings are no longer reported and need their attributions removed.
        final Set<FindingAttributionKey> reportedFindingAttributionKeys = reportedFindings.stream()
                .map(finding -> {
                    final Long vulnDbId = vulnDbIdByVulnIdAndSource.get(finding.vulnIdAndSource());
                    return vulnDbId != null
                            ? new FindingAttributionKey(finding.componentId(), vulnDbId, finding.analyzerName())
                            : null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        final var deleteFindingAttributionCommands = new HashSet<DeleteFindingAttributionCommand>();

        for (final FindingAttribution existingAttribution : existingFindingAttributions) {
            final var attributionKey = FindingAttributionKey.of(existingAttribution);

            // NB: We can't make assumptions for failed analyzers.
            // If an analyzer previously reported the finding,
            // and now failed, we cannot assume that the finding
            // is no longer reported. So keep it in that case.
            if (!reportedFindingAttributionKeys.contains(attributionKey)
                    && !failedAnalyzers.contains(attributionKey.analyzerName())) {
                deleteFindingAttributionCommands.add(
                        new DeleteFindingAttributionCommand(existingAttribution.id()));
            }
        }

        // TODO: Evaluate vulnerability policies for all active findings.

        useJdbiTransaction(handle -> {
            final var notificationSubjectDao = handle.attach(NotificationSubjectDao.class);

            final List<FindingKey> createdFindings = createFindings(handle, createFindingCommands);
            if (!createdFindings.isEmpty()) {
                LOGGER.debug("Created {} new finding(s)", createdFindings.size());
            }

            final int attributionsCreated = createFindingAttributions(handle, createFindingAttributionCommands);
            if (attributionsCreated > 0) {
                LOGGER.debug("Created {} new attribution(s)", attributionsCreated);
            }

            final int attributionsDeleted = deleteAttributions(handle, deleteFindingAttributionCommands);
            if (attributionsDeleted > 0) {
                LOGGER.debug("Removed {} stale attribution(s)", attributionsDeleted);
            }

            // TODO: Apply policy results (create/update analyses)

            // TODO: Clean this up.
            final var notifyComponentIds = new ArrayList<Long>();
            final var notifyVulnIds = new ArrayList<Long>();
            createdFindings.forEach(createdFinding -> {
                notifyComponentIds.add(createdFinding.componentId());
                notifyVulnIds.add(createdFinding.vulnerabilityId());
            });
            final List<Notification> notifications = notificationSubjectDao
                    .getForNewVulnerabilities(notifyComponentIds, notifyVulnIds)
                    .stream()
                    .map(subject -> createNewVulnerabilityNotification(
                            subject.getProject(),
                            subject.getComponent(),
                            subject.getVulnerability(),
                            "TODO"))
                    .toList();
            LOGGER.debug("Emitting {} notification(s)", notifications.size());
            new JdbiNotificationEmitter(handle).emitAll(notifications);
        });
    }

    private boolean canUpdateVulnerability(
            org.dependencytrack.model.Vulnerability.Source source,
            String analyzerName) {
        if ("internal".equals(analyzerName)) {
            return false;
        }
        if (org.dependencytrack.model.Vulnerability.Source.INTERNAL == source) {
            return false;
        }
        return isAuthoritativeSource(source, analyzerName)
                || (canBeMirrored(source) && !isMirroringEnabled(source));
    }

    private static boolean isAuthoritativeSource(
            org.dependencytrack.model.Vulnerability.Source source,
            String analyzerName) {
        return switch (analyzerName) {
            case "oss-index" -> org.dependencytrack.model.Vulnerability.Source.OSSINDEX == source;
            case "snyk" -> org.dependencytrack.model.Vulnerability.Source.SNYK == source;
            case "vuln-db" -> org.dependencytrack.model.Vulnerability.Source.VULNDB == source;
            default -> false;
        };
    }

    private static boolean canBeMirrored(org.dependencytrack.model.Vulnerability.Source source) {
        return switch (source) {
            case GITHUB, NVD, OSV, CSAF -> true;
            default -> false;
        };
    }

    private boolean isMirroringEnabled(org.dependencytrack.model.Vulnerability.Source source) {
        try {
            final var dataSourceFactory = (VulnDataSourceFactory) pluginManager
                    .getFactory(VulnDataSource.class, source.name().toLowerCase());
            return dataSourceFactory.isDataSourceEnabled();
        } catch (NoSuchExtensionException e) {
            return false;
        }
    }

    private record FindingKey(long componentId, long vulnerabilityId) {

        private static FindingKey of(FindingAttribution finding) {
            return new FindingKey(finding.componentId(), finding.vulnId());
        }

    }

    private record FindingAttributionKey(
            long componentId,
            long vulnerabilityId,
            String analyzerName) {

        private static FindingAttributionKey of(FindingAttribution finding) {
            return new FindingAttributionKey(
                    finding.componentId(),
                    finding.vulnId(),
                    finding.analyzerName());
        }

    }

    private record ReportedFinding(
            long componentId,
            VulnIdAndSource vulnIdAndSource,
            String analyzerName) {
    }

    private record ReportedVulnerability(
            Vulnerability vdrVuln,
            String analyzerName,
            @Nullable Long internalVulnId) {
    }

    private record ConvertedVulnerability(
            org.dependencytrack.model.@Nullable Vulnerability vuln,
            String analyzerName,
            @Nullable Long internalVulnId) {
    }

    private record CreateFindingCommand(FindingKey findingKey) {
    }

    private record CreateFindingAttributionCommand(
            long vulnId,
            long componentId,
            long projectId,
            String analyzerName) {
    }

    private record DeleteFindingAttributionCommand(long id) {
    }

    private record FindingAttribution(
            long id,
            long componentId,
            long vulnId,
            String analyzerName) {
    }

    private static List<FindingAttribution> getExistingFindingAttributions(Handle handle, long projectId) {
        return handle.createQuery("""
                        SELECT fa."ID"
                             , cv."COMPONENT_ID"
                             , cv."VULNERABILITY_ID"
                             , fa."ANALYZERIDENTITY"
                          FROM "COMPONENTS_VULNERABILITIES" AS cv
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = cv."COMPONENT_ID"
                         INNER JOIN "FINDINGATTRIBUTION" AS fa
                            ON fa."COMPONENT_ID" = cv."COMPONENT_ID"
                           AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                           AND fa."DELETED_AT" IS NULL
                         WHERE c."PROJECT_ID" = :projectId
                        """)
                .bind("projectId", projectId)
                .map((rs, ctx) -> new FindingAttribution(
                        rs.getLong("ID"),
                        rs.getLong("COMPONENT_ID"),
                        rs.getLong("VULNERABILITY_ID"),
                        rs.getString("ANALYZERIDENTITY")))
                .list();
    }

    private static List<FindingKey> createFindings(Handle handle, Collection<CreateFindingCommand> commands) {
        if (commands.isEmpty()) {
            return List.of();
        }

        final var componentIds = new long[commands.size()];
        final var vulnIds = new long[commands.size()];

        int i = 0;
        for (final CreateFindingCommand command : commands) {
            componentIds[i] = command.findingKey().componentId();
            vulnIds[i] = command.findingKey().vulnerabilityId();
            i++;
        }

        return handle.createUpdate("""
                        INSERT INTO "COMPONENTS_VULNERABILITIES" ("COMPONENT_ID", "VULNERABILITY_ID")
                        SELECT *
                          FROM UNNEST(:componentIds, :vulnIds)
                            AS t(component_id, vuln_id)
                         ORDER BY component_id
                                , vuln_id
                        ON CONFLICT DO NOTHING
                        RETURNING "COMPONENT_ID"
                                , "VULNERABILITY_ID"
                        """)
                .bind("componentIds", componentIds)
                .bind("vulnIds", vulnIds)
                .executeAndReturnGeneratedKeys()
                .map((rs, ctx) -> new FindingKey(
                        rs.getLong("COMPONENT_ID"),
                        rs.getLong("VULNERABILITY_ID")))
                .list();
    }

    private static int createFindingAttributions(Handle handle, Collection<CreateFindingAttributionCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        final var vulnIds = new long[commands.size()];
        final var componentIds = new long[commands.size()];
        final var projectIds = new long[commands.size()];
        final var analyzerIdentities = new String[commands.size()];

        int i = 0;
        for (final CreateFindingAttributionCommand command : commands) {
            vulnIds[i] = command.vulnId();
            componentIds[i] = command.componentId();
            projectIds[i] = command.projectId();
            analyzerIdentities[i] = command.analyzerName();
            i++;
        }

        return handle.createUpdate("""
                        INSERT INTO "FINDINGATTRIBUTION" AS fa (
                          "VULNERABILITY_ID"
                        , "COMPONENT_ID"
                        , "PROJECT_ID"
                        , "ANALYZERIDENTITY"
                        , "ATTRIBUTED_ON"
                        )
                        SELECT vuln_id
                             , component_id
                             , project_id
                             , analyzer_identity
                             , NOW()
                          FROM UNNEST(:vulnIds, :componentIds, :projectIds, :analyzerIdentities)
                            AS t(vuln_id, component_id, project_id, analyzer_identity)
                         ORDER BY vuln_id
                                , component_id
                                , analyzer_identity
                        ON CONFLICT ("VULNERABILITY_ID", "COMPONENT_ID", "ANALYZERIDENTITY") DO UPDATE
                        SET "ATTRIBUTED_ON" = EXCLUDED."ATTRIBUTED_ON"
                          , "DELETED_AT" = NULL
                        WHERE fa."DELETED_AT" IS NOT NULL
                        """)
                .bind("vulnIds", vulnIds)
                .bind("componentIds", componentIds)
                .bind("projectIds", projectIds)
                .bind("analyzerIdentities", analyzerIdentities)
                .execute();
    }

    private static int deleteAttributions(Handle handle, Collection<DeleteFindingAttributionCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        return handle.createUpdate("""
                        UPDATE "FINDINGATTRIBUTION"
                           SET "DELETED_AT" = NOW()
                         WHERE "ID" = ANY(:ids)
                           AND "DELETED_AT" IS NULL
                        """)
                .bind("ids", commands.stream().map(DeleteFindingAttributionCommand::id).toArray(Long[]::new))
                .execute();
    }

}
