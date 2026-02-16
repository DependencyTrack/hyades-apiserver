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
import org.dependencytrack.model.FindingAttributionKey;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.VulnIdAndSource;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.jdbi.AnalysisDao;
import org.dependencytrack.persistence.jdbi.AnalysisDao.Analysis;
import org.dependencytrack.persistence.jdbi.AnalysisDao.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.query.GetProjectAuditChangeNotificationSubjectQuery;
import org.dependencytrack.plugin.NoSuchExtensionException;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyEvaluator;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyOperation;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg.AnalyzerResult;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;
import static org.dependencytrack.notification.api.NotificationFactory.createNewVulnerabilityNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.parser.dependencytrack.BovModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
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

            vulnDetails.merge(
                    vulnIdAndSource,
                    new ReportedVulnerability(vdrVuln, analyzerName, internalVulnId),
                    (existing, incoming) -> {
                        // Prefer vulnerabilities identified from the internal database.
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

        return inJdbiTransaction(
                handle -> new VulnerabilityDao(handle).syncMany(
                        convertedVulnByVulnIdAndSource,
                        this::canUpdateVulnerability));
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

        // Fetch all existing finding attributions for the project.
        // This excludes attributions that have previously been soft-deleted.
        // Group them by finding key for easier access during reconciliation.
        final List<FindingDao.FindingAttribution> existingAttributions =
                withJdbiHandle(handle -> new FindingDao(handle).getExistingAttributions(projectId));
        final Map<FindingKey, List<FindingDao.FindingAttribution>> existingAttributionsByFindingKey =
                existingAttributions.stream()
                        .collect(Collectors.groupingBy(
                                attribution -> new FindingKey(attribution.componentId(), attribution.vulnDbId())));

        LOGGER.debug(
                "Found {} existing finding attribution(s) and {} unique finding(s)",
                existingAttributions.size(),
                existingAttributionsByFindingKey.size());

        final var findingsToCreate = new HashSet<FindingKey>();
        final var createAttributionCommands = new HashSet<FindingDao.CreateAttributionCommand>();
        final var reportedAttributionKeys = new HashSet<FindingAttributionKey>();

        for (final ReportedFinding reportedFinding : reportedFindings) {
            final Long vulnDbId = vulnDbIdByVulnIdAndSource.get(reportedFinding.vulnIdAndSource());
            if (vulnDbId == null) {
                LOGGER.warn(
                        "Vulnerability {} not found in database; Skipping",
                        reportedFinding.vulnIdAndSource());
                continue;
            }

            reportedAttributionKeys.add(
                    new FindingAttributionKey(
                            new FindingKey(reportedFinding.componentId(), vulnDbId),
                            reportedFinding.analyzerName()));

            final var findingKey = new FindingKey(reportedFinding.componentId(), vulnDbId);
            final List<FindingDao.FindingAttribution> existingFindingAttributionsForKey =
                    existingAttributionsByFindingKey.get(findingKey);

            final boolean findingExists =
                    existingFindingAttributionsForKey != null
                            && !existingFindingAttributionsForKey.isEmpty();
            if (!findingExists) {
                findingsToCreate.add(findingKey);
            }

            final boolean hasAttribution =
                    existingFindingAttributionsForKey != null
                            && existingFindingAttributionsForKey.stream()
                            .anyMatch(ef -> ef.analyzerName().equals(reportedFinding.analyzerName()));
            if (!hasAttribution) {
                createAttributionCommands.add(
                        new FindingDao.CreateAttributionCommand(
                                vulnDbId,
                                reportedFinding.componentId(),
                                projectId,
                                reportedFinding.analyzerName()));
            }
        }

        // Determine which attributions are no longer applicable, and should be deleted.
        final var attributionIdsToDelete = new HashSet<Long>();
        for (final FindingDao.FindingAttribution existingAttribution : existingAttributions) {
            final var attributionKey = new FindingAttributionKey(
                    new FindingKey(existingAttribution.componentId(), existingAttribution.vulnDbId()),
                    existingAttribution.analyzerName());

            // NB: If an analyzer previously reported the finding,
            // and now failed, we cannot assume that the finding
            // is no longer reported. So keep it in that case.
            if (!reportedAttributionKeys.contains(attributionKey)
                    && !failedAnalyzers.contains(attributionKey.analyzerName())) {
                attributionIdsToDelete.add(existingAttribution.id());
            }
        }

        // Evaluate vulnerability policies, if there are any.
        // Only evaluate policies for active findings (i.e. those with >=1 attributions).
        final Map<Long, Set<Long>> vulnDbIdsByComponentId =
                computeActiveFindings(
                        existingAttributionsByFindingKey,
                        attributionIdsToDelete,
                        findingsToCreate,
                        createAttributionCommands);
        final Map<Long, Map<Long, VulnerabilityPolicy>> policyResults =
                evaluateVulnPolicies(projectId, vulnDbIdsByComponentId);

        // Flush all computed changes to the database in a single transaction.
        // Note that this is done for both performance and idempotency reasons.
        // Since this activity may be retried, we cannot commit partial changes.
        useJdbiTransaction(handle -> {
            final var notificationSubjectDao = handle.attach(NotificationSubjectDao.class);
            final var findingDao = new FindingDao(handle);

            final List<FindingKey> createdFindings = findingDao.createFindings(findingsToCreate);
            LOGGER.debug("Created {} new finding(s)", createdFindings.size());

            final int attributionsCreated = findingDao.createAttributions(createAttributionCommands);
            LOGGER.debug("Created {} new attribution(s)", attributionsCreated);

            final int attributionsDeleted = findingDao.deleteAttributions(attributionIdsToDelete);
            LOGGER.debug("Removed {} stale attribution(s)", attributionsDeleted);

            final List<Notification> auditChangeNotifications =
                    applyVulnPolicyResults(handle, projectId, policyResults, vulnDbIdsByComponentId);

            // TODO: Clean this up.
            final var notifications = new ArrayList<>(auditChangeNotifications);
            final var notifyComponentIds = new ArrayList<Long>();
            final var notifyVulnIds = new ArrayList<Long>();
            createdFindings.forEach(createdFinding -> {
                notifyComponentIds.add(createdFinding.componentId());
                notifyVulnIds.add(createdFinding.vulnDbId());
            });
            notificationSubjectDao
                    .getForNewVulnerabilities(notifyComponentIds, notifyVulnIds)
                    .stream()
                    .map(subject -> createNewVulnerabilityNotification(
                            subject.getProject(),
                            subject.getComponent(),
                            subject.getVulnerability(),
                            "TODO"))
                    .forEach(notifications::add);


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

    private static Map<Long, Set<Long>> computeActiveFindings(
            Map<FindingKey, List<FindingDao.FindingAttribution>> existingAttributionsByFindingKey,
            Set<Long> attributionIdsToDelete,
            Set<FindingKey> findingsToCreate,
            Set<FindingDao.CreateAttributionCommand> createAttributionCommands) {
        final var activeFindings = new HashMap<Long, Set<Long>>();

        // Consider existing findings as active if at least one
        // existing attribution is NOT scheduled for deletion.
        for (final var entry : existingAttributionsByFindingKey.entrySet()) {
            final FindingKey findingKey = entry.getKey();
            final List<FindingDao.FindingAttribution> existingAttributions = entry.getValue();

            final boolean allAttributionsDeleted = existingAttributions.stream()
                    .map(FindingDao.FindingAttribution::id)
                    .allMatch(attributionIdsToDelete::contains);
            if (!allAttributionsDeleted) {
                activeFindings
                        .computeIfAbsent(findingKey.componentId(), k -> new HashSet<>())
                        .add(findingKey.vulnDbId());
            }
        }

        // Findings that are scheduled for creation are inherently active.
        for (final FindingKey findingKey : findingsToCreate) {
            activeFindings
                    .computeIfAbsent(findingKey.componentId(), k -> new HashSet<>())
                    .add(findingKey.vulnDbId());
        }

        // Handle the case where a finding:
        //   * Was previously reported by analyzer A.
        //   * Is no longer reported by analyzer A (i.e. its attribution is in attributionIdsToDelete).
        //   * Is now reported by analyzer B.
        // Because the finding already existed, it won't be in findingsToCreate.
        // But an attribution for analyzer B is scheduled for creation,
        // which tells us that the finding is still active.
        for (final FindingDao.CreateAttributionCommand command : createAttributionCommands) {
            activeFindings
                    .computeIfAbsent(command.componentId(), k -> new HashSet<>())
                    .add(command.vulnDbId());
        }

        return activeFindings;
    }

    private Map<Long, Map<Long, VulnerabilityPolicy>> evaluateVulnPolicies(
            long projectId,
            Map<Long, Set<Long>> vulnIdsByComponentId) {
        if (vulnIdsByComponentId.isEmpty()) {
            return Map.of();
        }

        final Map<Long, Map<Long, VulnerabilityPolicy>> evaluationResult =
                vulnPolicyEvaluator.evaluateAll(projectId, vulnIdsByComponentId);
        if (evaluationResult.isEmpty()) {
            LOGGER.debug("Vulnerability policy evaluation did not yield any results");
            return Map.of();
        }

        // Policies with mode LOG do not require any database changes.
        // Log them now, and omit them from the result returned by this method.
        final var applicableResult = new HashMap<Long, Map<Long, VulnerabilityPolicy>>();
        for (final var entry : evaluationResult.entrySet()) {
            final long componentId = entry.getKey();
            final Map<Long, VulnerabilityPolicy> policyByVulnDbId = entry.getValue();

            for (final var vulnEntry : policyByVulnDbId.entrySet()) {
                final long vulnDbId = vulnEntry.getKey();
                final VulnerabilityPolicy policy = vulnEntry.getValue();

                if (policy.getOperationMode() == VulnerabilityPolicyOperation.LOG) {
                    LOGGER.info(
                            "Vulnerability policy '{}' matched for component {} and vulnerability {}",
                            policy.getName(),
                            componentId,
                            vulnDbId);
                    continue;
                }

                applicableResult
                        .computeIfAbsent(componentId, k -> new HashMap<>())
                        .put(vulnEntry.getKey(), policy);
            }
        }

        return applicableResult;
    }

    private List<Notification> applyVulnPolicyResults(
            Handle handle,
            long projectId,
            Map<Long, Map<Long, VulnerabilityPolicy>> policyResults,
            Map<Long, Set<Long>> activeFindings) {
        final var analysisDao = new AnalysisDao(handle);
        final var reconcileResults = new ArrayList<AnalysisReconciler.Result>();

        // Collect finding keys that have applicable policy results.
        final Set<FindingKey> policyFindingKeys = policyResults.entrySet().stream()
                .flatMap(entry -> {
                    final long componentId = entry.getKey();
                    return entry.getValue().keySet().stream()
                            .map(vulnDbId -> new FindingKey(componentId, vulnDbId));
                })
                .collect(Collectors.toSet());

        // Apply policies to findings that have matching policy results.
        if (!policyFindingKeys.isEmpty()) {
            final Map<FindingKey, Analysis> existingAnalysisByFindingKey =
                    analysisDao.getForProjectFindings(projectId, policyFindingKeys);
            LOGGER.debug("Found {} existing analyses for {} finding(s) with policy results",
                    existingAnalysisByFindingKey.size(), policyFindingKeys.size());

            for (final var componentEntry : policyResults.entrySet()) {
                final long componentId = componentEntry.getKey();
                final Map<Long, VulnerabilityPolicy> policyByVulnDbId = componentEntry.getValue();

                for (final var vulnEntry : policyByVulnDbId.entrySet()) {
                    final long vulnDbId = vulnEntry.getKey();
                    final VulnerabilityPolicy policy = vulnEntry.getValue();

                    final var findingKey = new FindingKey(componentId, vulnDbId);
                    final Analysis existingAnalysis = existingAnalysisByFindingKey.get(findingKey);
                    LOGGER.debug("Reconciling analysis for {}", findingKey);

                    final var analysisReconciler = new AnalysisReconciler(projectId, componentId, vulnDbId, existingAnalysis);
                    final AnalysisReconciler.Result reconcileResult = analysisReconciler.reconcile(policy);
                    if (reconcileResult != null) {
                        reconcileResults.add(reconcileResult);
                    }
                }
            }
        }

        // Reset stale analyses that were previously applied by a policy,
        // but whose corresponding finding no longer has a matching policy.
        // This may happen when policies are removed, or their conditions are modified.
        final Map<FindingKey, Analysis> staleAnalysisByFindingKey =
                analysisDao.getForProjectWithPolicyApplied(projectId, policyFindingKeys);
        for (final var entry : staleAnalysisByFindingKey.entrySet()) {
            final FindingKey findingKey = entry.getKey();
            final Analysis analysis = entry.getValue();

            final Set<Long> activeVulnIds = activeFindings.get(findingKey.componentId());
            if (activeVulnIds == null || !activeVulnIds.contains(findingKey.vulnDbId())) {
                continue;
            }

            LOGGER.debug("Un-applying stale policy analysis for {}", findingKey);
            final var reconciler = new AnalysisReconciler(projectId, findingKey.componentId(), findingKey.vulnDbId(), analysis);
            final AnalysisReconciler.Result unapplyResult = reconciler.reconcileForNoPolicy();
            if (unapplyResult != null) {
                reconcileResults.add(unapplyResult);
            }
        }

        if (reconcileResults.isEmpty()) {
            LOGGER.debug("All analyses are already in desired state");
            return List.of();
        }

        // Create or update analyses according to the reconciliation results.
        final List<MakeAnalysisCommand> makeAnalysisCommands =
                reconcileResults.stream()
                        .map(AnalysisReconciler.Result::makeAnalysisCommand)
                        .toList();
        final Map<FindingKey, Long> modifiedAnalysisIdByFindingKey = analysisDao.makeAnalyses(makeAnalysisCommands);
        LOGGER.debug("Modified {} analysis record(s)", modifiedAnalysisIdByFindingKey.size());

        // Populate the audit trail for analyses that have actually changed.
        final var createCommentCommands = new ArrayList<AnalysisDao.CreateCommentCommand>();
        for (final var reconcileResult : reconcileResults) {
            final Long analysisId = modifiedAnalysisIdByFindingKey.get(reconcileResult.findingKey());
            if (analysisId != null) {
                createCommentCommands.addAll(reconcileResult.createCommentCommands(analysisId));
            }
        }
        final int commentsCreated = analysisDao.createComments(createCommentCommands);
        LOGGER.debug("Created {} analysis comment(s)", commentsCreated);

        // Build notifications for analyses where state or suppression changed.
        final List<AnalysisReconciler.Result> auditChangeResults =
                reconcileResults.stream()
                        .filter(result -> result.analysisStateChanged() || result.suppressionChanged())
                        .toList();
        if (auditChangeResults.isEmpty()) {
            return List.of();
        }

        final List<GetProjectAuditChangeNotificationSubjectQuery> notificationSubjectQueries =
                auditChangeResults.stream()
                        .map(result -> new GetProjectAuditChangeNotificationSubjectQuery(
                                result.findingKey().componentId(),
                                result.findingKey().vulnDbId(),
                                result.makeAnalysisCommand().state(),
                                result.makeAnalysisCommand().suppressed()))
                        .toList();

        final var notificationSubjectDao = handle.attach(NotificationSubjectDao.class);
        final List<VulnerabilityAnalysisDecisionChangeSubject> subjects =
                notificationSubjectDao.getForProjectAuditChanges(notificationSubjectQueries);

        final var notifications = new ArrayList<Notification>(subjects.size());
        for (int i = 0; i < subjects.size(); i++) {
            final AnalysisReconciler.Result result = auditChangeResults.get(i);
            final VulnerabilityAnalysisDecisionChangeSubject subject = subjects.get(i);
            notifications.add(
                    createVulnerabilityAnalysisDecisionChangeNotification(
                            subject.getProject(),
                            subject.getComponent(),
                            subject.getVulnerability(),
                            subject.getAnalysis(),
                            result.analysisStateChanged(),
                            result.suppressionChanged()));
        }

        return notifications;
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

}
