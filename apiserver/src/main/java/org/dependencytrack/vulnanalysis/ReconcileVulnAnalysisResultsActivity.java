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
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.VulnIdAndSource;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
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
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;
import static org.dependencytrack.parser.dependencytrack.BovModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.VulnerabilityUtil.canBeMirrored;
import static org.dependencytrack.util.VulnerabilityUtil.isAuthoritativeSource;

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

        try (var ignored = MDC.putCloseable(MDC_PROJECT_UUID, arg.getProjectUuid())) {
            LOGGER.info(
                    "Reconciling results from {} vulnerability analyzers",
                    arg.getAnalyzerResultsCount());

            final var successfulAnalyzers = new HashSet<String>();
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

                    successfulAnalyzers.add(analyzerName);
                    extractFindingsFromVdr(analyzerName, vdr, reportedFindings, vulnDetailsByKey);
                }
            }

            if (successfulAnalyzers.isEmpty()) {
                LOGGER.warn("No successful analyzers; skipping reconciliation");
                return null;
            }

            LOGGER.debug(
                    "Extracted {} findings and {} unique vulnerabilities from VDRs",
                    reportedFindings.size(),
                    vulnDetailsByKey.size());

            final Map<VulnIdAndSource, ConvertedVulnerability> convertedVulns =
                    convertVulnerabilities(vulnDetailsByKey);
            LOGGER.debug("Converted {} vulnerabilities", convertedVulns.size());

            LOGGER.debug("Synchronizing {} vulnerabilities", convertedVulns.size());
            final Map<VulnIdAndSource, Long> vulnIdAndSourceByDbId = syncVulnerabilities(convertedVulns);
            LOGGER.debug("Synchronized {} vulnerabilities", vulnIdAndSourceByDbId.size());

            reconcileFindings(
                    arg.getProjectUuid(),
                    reportedFindings,
                    vulnIdAndSourceByDbId,
                    successfulAnalyzers,
                    failedAnalyzers);
        }

        return null;
    }

    private static void extractFindingsFromVdr(
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
                    LOGGER.warn("Encountered invalid BOM ref '{}' for vulnerability '{}'",
                            affects.getRef(), vulnIdAndSource, e);
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

    private Map<VulnIdAndSource, ConvertedVulnerability> convertVulnerabilities(
            Map<VulnIdAndSource, ReportedVulnerability> detailsByVulnIdAndSource) {
        final var converted = new HashMap<VulnIdAndSource, ConvertedVulnerability>();

        for (final var entry : detailsByVulnIdAndSource.entrySet()) {
            final VulnIdAndSource vulnIdAndSource = entry.getKey();
            final ReportedVulnerability extracted = entry.getValue();

            // If internal vulnerability ID is set, no conversion needed
            if (extracted.internalVulnId() != null) {
                converted.put(vulnIdAndSource, new ConvertedVulnerability(
                        null, extracted.analyzerName(), extracted.internalVulnId()));
                continue;
            }

            // Convert CycloneDX to internal model (expensive, do outside transaction)
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

    private Map<VulnIdAndSource, Long> syncVulnerabilities(
            Map<VulnIdAndSource, ConvertedVulnerability> convertedVulns) {
        final var results = new HashMap<VulnIdAndSource, Long>(convertedVulns.size());

        // If all vulnerabilities are internal, we don't need to sync anything
        // and can simply short-circuit here, without performing any SQL queries.
        for (final var entry : convertedVulns.entrySet()) {
            if (entry.getValue().internalVulnId() != null) {
                results.put(entry.getKey(), entry.getValue().internalVulnId());
            }
        }
        if (results.size() == convertedVulns.size()) {
            return results;
        }

        final int vulnsToSyncCount = convertedVulns.size() - results.size();
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

        int i = 0;
        for (final var entry : convertedVulns.entrySet()) {
            if (entry.getValue().internalVulnId() == null) {
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
                canUpdateArray[i] = canUpdateVulnerability(
                        vuln, mapToAnalyzerIdentity(entry.getValue().analyzerName()));
            }
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
                           , severity
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
                        , severity
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
                           , CAST(severity AS severity)
                           , vulnerable_versions
                           , patched_versions
                           , GEN_RANDOM_UUID()
                        FROM cte_input
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
                      WHERE EXISTS (
                              SELECT 1
                                FROM cte_input AS i
                               WHERE i.vuln_id = v."VULNID"
                                 AND i.source = v."SOURCE"
                                 AND i.can_update
                            )
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
            String projectUuid,
            List<ReportedFinding> reportedFindings,
            Map<VulnIdAndSource, Long> vulnIdAndSourceByDbId,
            Set<String> successfulAnalyzers,
            Set<String> failedAnalyzers) {
        final Long projectId = withJdbiHandle(handle -> getProjectIdByUuid(handle, projectUuid));
        if (projectId == null) {
            throw new TerminalApplicationFailureException("Project does not exist");
        }

        final List<ExistingFinding> existingFindings =
                withJdbiHandle(handle -> getExistingFindings(handle, projectId));
        final Map<FindingId, List<ExistingFinding>> existingFindingByKey =
                existingFindings.stream()
                        .collect(Collectors.groupingBy(FindingId::of));

        LOGGER.debug("Found {} existing findings", existingFindings.size());

        final var createFindingCommands = new ArrayList<CreateFindingCommand>();
        final var createFindingAttributionCommands = new ArrayList<CreateFindingAttributionCommand>();

        for (final ReportedFinding extracted : reportedFindings) {
            final Long vulnDbId = vulnIdAndSourceByDbId.get(extracted.vulnIdAndSource());
            if (vulnDbId == null) {
                LOGGER.warn("Vulnerability {} not found in database, skipping", extracted.vulnIdAndSource());
                continue;
            }

            final var findingKey = new FindingId(extracted.componentId(), vulnDbId);
            final List<ExistingFinding> existingForKey = existingFindingByKey.get(findingKey);

            final boolean findingExists = existingForKey != null && !existingForKey.isEmpty();
            final boolean hasAttribution = existingForKey != null
                    && existingForKey.stream().anyMatch(ef -> ef.analyzerIdentity().equals(extracted.analyzerName()));

            if (!findingExists) {
                createFindingCommands.add(new CreateFindingCommand(extracted.componentId(), vulnDbId));
            }

            if (!hasAttribution) {
                createFindingAttributionCommands.add(new CreateFindingAttributionCommand(
                        vulnDbId,
                        extracted.componentId(),
                        projectId,
                        mapToAnalyzerIdentity(extracted.analyzerName())));
            }
        }

        final Set<FindingAttributionKey> currentFindingAttributionKeys = reportedFindings.stream()
                .map(finding -> {
                    final Long vulnDbId = vulnIdAndSourceByDbId.get(finding.vulnIdAndSource());
                    return vulnDbId != null
                            ? new FindingAttributionKey(finding.componentId(), vulnDbId, finding.analyzerName())
                            : null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        final var deleteFindingAttributionCommands = new ArrayList<DeleteFindingAttributionCommand>();
        final var suppressFindingCommands = new ArrayList<SuppressFindingCommand>();

        for (final ExistingFinding existing : existingFindings) {
            // Only consider attributions from analyzers that succeeded this run.
            if (!successfulAnalyzers.contains(existing.analyzerIdentity())) {
                continue;
            }

            final var attributionKey = FindingAttributionKey.of(existing);
            if (!currentFindingAttributionKeys.contains(attributionKey)) {
                // This attribution is no longer reported by the analyzer.
                deleteFindingAttributionCommands.add(new DeleteFindingAttributionCommand(existing.attributionId()));

                // Check if any other attribution remains for this finding
                final List<ExistingFinding> allAttributionsForFinding =
                        existingFindingByKey.get(FindingId.of(existing));

                // Count attributions that will remain after removal:
                // - Attributions from failed analyzers (we can't make assumptions about them)
                // - Attributions that are still being reported
                final boolean hasRemainingAttributions = allAttributionsForFinding.stream()
                        .filter(ef -> !deleteFindingAttributionCommands.contains(
                                new DeleteFindingAttributionCommand(ef.attributionId())))
                        .anyMatch(ef -> failedAnalyzers.contains(ef.analyzerIdentity())
                                || currentFindingAttributionKeys.contains(new FindingAttributionKey(
                                ef.componentId(), ef.vulnId(), ef.analyzerIdentity())));

                if (!hasRemainingAttributions) {
                    // No analyzer reports this finding anymore, suppress it
                    suppressFindingCommands.add(new SuppressFindingCommand(
                            existing.componentId(),
                            existing.vulnId(),
                            projectId));
                }
            }
        }

        useJdbiTransaction(handle -> {
            final int findingsCreated = createFindings(handle, createFindingCommands);
            if (findingsCreated > 0) {
                LOGGER.debug("Created {} new findings", findingsCreated);
            }

            final int attributionsCreated = createFindingAttributions(handle, createFindingAttributionCommands);
            if (attributionsCreated > 0) {
                LOGGER.debug("Created {} new attributions", attributionsCreated);
            }

            final int attributionsDeleted = deleteAttributions(handle, deleteFindingAttributionCommands);
            if (attributionsDeleted > 0) {
                LOGGER.debug("Removed {} stale attributions", attributionsDeleted);
            }

            final int analysesSuppressed = suppressAnalyses(handle, suppressFindingCommands);
            if (analysesSuppressed > 0) {
                LOGGER.debug("Suppressed {} findings", analysesSuppressed);

                // TODO: Create analysis comments explaining the suppression
                // TODO: Emit notifications for suppression changes
            }
        });

        // TODO: 9. Evaluate vulnerability policies for all current findings
        // TODO: 10. Apply policy results (create/update analyses)
        // TODO: 11. Emit notifications for new findings
    }

    private AnalyzerIdentity mapToAnalyzerIdentity(String analyzerName) {
        return switch (analyzerName.toLowerCase()) {
            case "internal" -> AnalyzerIdentity.INTERNAL_ANALYZER;
            case "oss-index" -> AnalyzerIdentity.OSSINDEX_ANALYZER;
            case "snyk" -> AnalyzerIdentity.SNYK_ANALYZER;
            default -> AnalyzerIdentity.NONE;
        };
    }

    private boolean canUpdateVulnerability(
            org.dependencytrack.model.Vulnerability vuln,
            AnalyzerIdentity analyzer) {
        if (analyzer == AnalyzerIdentity.INTERNAL_ANALYZER) {
            return false;
        }
        if (org.dependencytrack.model.Vulnerability.Source.INTERNAL.name().equals(vuln.getSource())) {
            return false;
        }
        return isAuthoritativeSource(vuln, analyzer)
                || (canBeMirrored(vuln) && !isMirroringEnabled(vuln));
    }

    private boolean isMirroringEnabled(org.dependencytrack.model.Vulnerability vuln) {
        try {
            final var dataSourceFactory = (VulnDataSourceFactory) pluginManager
                    .getFactory(VulnDataSource.class, vuln.getSource().toLowerCase());
            return dataSourceFactory.isDataSourceEnabled();
        } catch (NoSuchExtensionException e) {
            return false;
        }
    }

    private record FindingId(long componentId, long vulnerabilityId) {

        private static FindingId of(ExistingFinding finding) {
            return new FindingId(finding.componentId(), finding.vulnId());
        }

    }

    private record FindingAttributionKey(
            long componentId,
            long vulnerabilityId,
            String analyzerIdentity) {

        private static FindingAttributionKey of(ExistingFinding finding) {
            return new FindingAttributionKey(
                    finding.componentId(),
                    finding.vulnId(),
                    finding.analyzerIdentity());
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

    private record CreateFindingCommand(long componentId, long vulnerabilityId) {
    }

    private record CreateFindingAttributionCommand(
            long vulnId,
            long componentId,
            long projectId,
            AnalyzerIdentity analyzerIdentity) {
    }

    private record DeleteFindingAttributionCommand(long id) {
    }

    private record ExistingFinding(
            long componentId,
            long vulnId,
            long attributionId,
            String analyzerIdentity) {
    }

    private record SuppressFindingCommand(long componentId, long vulnerabilityId, long projectId) {
    }

    private static @Nullable Long getProjectIdByUuid(Handle handle, String uuid) {
        return handle.createQuery("""
                        SELECT "ID" FROM "PROJECT" WHERE "UUID" = CAST(:uuid AS UUID)
                        """)
                .bind("uuid", uuid)
                .mapTo(Long.class)
                .findOne()
                .orElse(null);
    }

    private static List<ExistingFinding> getExistingFindings(Handle handle, long projectId) {
        return handle.createQuery("""
                        SELECT cv."COMPONENT_ID"
                             , cv."VULNERABILITY_ID"
                             , fa."ID"
                             , fa."ANALYZERIDENTITY"
                          FROM "COMPONENTS_VULNERABILITIES" AS cv
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = cv."COMPONENT_ID"
                         INNER JOIN "FINDINGATTRIBUTION" AS fa
                            ON fa."COMPONENT_ID" = cv."COMPONENT_ID"
                           AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                         WHERE c."PROJECT_ID" = :projectId
                        """)
                .bind("projectId", projectId)
                .map((rs, ctx) -> new ExistingFinding(
                        rs.getLong("COMPONENT_ID"),
                        rs.getLong("VULNERABILITY_ID"),
                        rs.getLong("ID"),
                        rs.getString("ANALYZERIDENTITY")))
                .list();
    }

    private static int createFindings(Handle handle, List<CreateFindingCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        final var componentIds = new long[commands.size()];
        final var vulnIds = new long[commands.size()];

        for (int i = 0; i < commands.size(); i++) {
            componentIds[i] = commands.get(i).componentId();
            vulnIds[i] = commands.get(i).vulnerabilityId();
        }

        return handle.createUpdate("""
                        INSERT INTO "COMPONENTS_VULNERABILITIES" ("COMPONENT_ID", "VULNERABILITY_ID")
                        SELECT * FROM UNNEST(:componentIds, :vulnIds)
                        ON CONFLICT DO NOTHING
                        """)
                .bind("componentIds", componentIds)
                .bind("vulnIds", vulnIds)
                .execute();
    }

    private static int createFindingAttributions(Handle handle, List<CreateFindingAttributionCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        final var vulnIds = new long[commands.size()];
        final var componentIds = new long[commands.size()];
        final var projectIds = new long[commands.size()];
        final var analyzerIdentities = new String[commands.size()];

        for (int i = 0; i < commands.size(); i++) {
            vulnIds[i] = commands.get(i).vulnId();
            componentIds[i] = commands.get(i).componentId();
            projectIds[i] = commands.get(i).projectId();
            analyzerIdentities[i] = commands.get(i).analyzerIdentity().name();
        }

        return handle.createUpdate("""
                        INSERT INTO "FINDINGATTRIBUTION" (
                          "VULNERABILITY_ID"
                        , "COMPONENT_ID"
                        , "PROJECT_ID"
                        , "ANALYZERIDENTITY"
                        , "UUID"
                        , "ATTRIBUTED_ON"
                        )
                        SELECT vuln_id
                             , component_id
                             , project_id
                             , analyzer_identity
                             , GEN_RANDOM_UUID()
                             , NOW()
                          FROM UNNEST(:vulnIds, :componentIds, :projectIds, :analyzerIdentities)
                            AS t(vuln_id, component_id, project_id, analyzer_identity)
                        ON CONFLICT ("VULNERABILITY_ID", "COMPONENT_ID", "ANALYZERIDENTITY") DO NOTHING
                        """)
                .bind("vulnIds", vulnIds)
                .bind("componentIds", componentIds)
                .bind("projectIds", projectIds)
                .bind("analyzerIdentities", analyzerIdentities)
                .execute();
    }

    private static int deleteAttributions(Handle handle, List<DeleteFindingAttributionCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        final var ids = new long[commands.size()];
        for (int i = 0; i < commands.size(); i++) {
            ids[i] = commands.get(i).id();
        }

        return handle.createUpdate("""
                        DELETE
                          FROM "FINDINGATTRIBUTION"
                         WHERE "ID" = ANY(:ids)
                        """)
                .bind("ids", ids)
                .execute();
    }

    private static int suppressAnalyses(Handle handle, List<SuppressFindingCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        final var componentIds = new long[commands.size()];
        final var projectIds = new long[commands.size()];
        final var vulnIds = new long[commands.size()];

        for (int i = 0; i < commands.size(); i++) {
            componentIds[i] = commands.get(i).componentId();
            projectIds[i] = commands.get(i).projectId();
            vulnIds[i] = commands.get(i).vulnerabilityId();
        }

        return handle.createUpdate("""
                        INSERT INTO "ANALYSIS" (
                          "COMPONENT_ID"
                        , "VULNERABILITY_ID"
                        , "PROJECT_ID"
                        , "SUPPRESSED"
                        , "STATE"
                        )
                        SELECT component_id
                             , vuln_id
                             , project_id
                             , TRUE
                             , 'FALSE_POSITIVE'
                          FROM UNNEST(:componentIds, :projectIds, :vulnIds)
                            AS t(component_id, project_id, vuln_id)
                        ON CONFLICT ("COMPONENT_ID", "VULNERABILITY_ID", "PROJECT_ID") DO UPDATE
                        SET "SUPPRESSED" = TRUE
                        WHERE "ANALYSIS"."SUPPRESSED" IS NULL
                           OR "ANALYSIS"."SUPPRESSED" = FALSE
                        """)
                .bind("componentIds", componentIds)
                .bind("projectIds", projectIds)
                .bind("vulnIds", vulnIds)
                .execute();
    }

}
