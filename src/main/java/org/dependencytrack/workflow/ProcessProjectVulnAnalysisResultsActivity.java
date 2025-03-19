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

import alpine.Config;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.mapping.PolicyProtoMapper;
import org.dependencytrack.parser.dependencytrack.ModelConverterCdxToVuln;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyEvaluator;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.framework.ActivityClient;
import org.dependencytrack.workflow.framework.ActivityContext;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.dependencytrack.workflow.payload.proto.v1alpha1.ProcessProjectVulnAnalysisResultsArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.Project;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Activity(name = "process-project-vuln-analysis-results")
public class ProcessProjectVulnAnalysisResultsActivity implements ActivityExecutor<ProcessProjectVulnAnalysisResultsArgs, Void> {

    public record FindingId(long componentId, String vulnId) {
    }

    public record FindingAttribution(
            long componentId,
            long vulnerabilityId,
            String analyzerIdentity,
            Instant attributedOn) {
    }

    public static final ActivityClient<ProcessProjectVulnAnalysisResultsArgs, Void> CLIENT =
            ActivityClient.of(
                    ProcessProjectVulnAnalysisResultsActivity.class,
                    protoConverter(ProcessProjectVulnAnalysisResultsArgs.class),
                    voidConverter());

    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessProjectVulnAnalysisResultsActivity.class);

    private final VulnerabilityPolicyEvaluator vulnPolicyEvaluator;

    public ProcessProjectVulnAnalysisResultsActivity() {
        this.vulnPolicyEvaluator =
                Config.getInstance().getPropertyAsBoolean(ConfigKey.VULNERABILITY_POLICY_ANALYSIS_ENABLED)
                        ? ServiceLoader.load(VulnerabilityPolicyEvaluator.class).findFirst().orElseThrow()
                        : null;
    }

    @Override
    public Optional<Void> execute(final ActivityContext<ProcessProjectVulnAnalysisResultsArgs> ctx) throws Exception {
        final ProcessProjectVulnAnalysisResultsArgs args =
                ctx.argument().orElseThrow(ApplicationFailureException::forMissingArguments);

        final Long projectId = getProjectId(args.getProject());
        if (projectId == null) {
            throw new ApplicationFailureException(
                    "Project with UUID %s does not exist".formatted(
                            args.getProject().getUuid()), null, true);
        }

        final var resultsFileMetadataSet = new HashSet<FileMetadata>(args.getResultsCount());
        final var vdrByAnalyzerName = new HashMap<String, Bom>(args.getResultsCount());
        final var failedAnalyzers = new HashSet<String>();

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            for (final ProcessProjectVulnAnalysisResultsArgs.Result result : args.getResultsList()) {
                if (result.hasFailureReason()) {
                    failedAnalyzers.add(result.getAnalyzer());
                } else if (!result.hasVdrFileMetadata()) {
                    throw new ApplicationFailureException("Result has neither failure reason nor VDR file", null, true);
                }

                resultsFileMetadataSet.add(result.getVdrFileMetadata());

                // TODO: Fail with a terminal exception when a file was not found?
                //  Consider checking for all files first so we can report when more
                //  than one file is missing.
                LOGGER.debug("Retrieving VDR file {}", result.getVdrFileMetadata().getLocation());
                final byte[] fileContent = fileStorage.get(result.getVdrFileMetadata());
                vdrByAnalyzerName.put(result.getAnalyzer(), Bom.parseFrom(fileContent));
            }
        }

        LOGGER.debug("Processing {} results", vdrByAnalyzerName.size());

        // TODO:
        //   1. Collect unique vulnerabilities across all results.
        //     a. If multiple analyzers report the same vulnerability,
        //        use a deterministic algorithm to pick the data we want to use.
        //   2. Synchronize vulnerabilities with database if needed (single trx, batching).
        //     a. Internal analyzer only reports vulnId & source, not sync needed for that.
        //     b. Be mindful of unique constraint errors upon trx commit. Is very likely
        //        when new vulns are reported multiple times in parallel.
        //   3. Load applicable vulnerability policies.
        //   4. Map synchronized vulnerabilities to component IDs.
        //     a. Keep track of which analyzer reported what. That allows us to automatically
        //        suppress findings that no analyzer reports anymore.
        //   5. Synchronize component<->vulnerability relationships with database (single trx, batching).
        //   6. Evaluate vulnerability policies.
        //   7. Apply policy results if needed (single trx, batching).
        //  Most of this already exists in VulnerabilityScanResultProcessor.
        //  The difference is that the processor does all this for a single component at a time,
        //  whereas here we'll deal with all components of a project.

        final var analyzersByReportedFindingId = new HashMap<FindingId, Set<String>>();
        final var reportedVulnsByVulnId = new HashMap<String, Set<Vulnerability>>();
        final var vulnIdsByComponentId = new HashMap<Long, Set<String>>();

        for (final Map.Entry<String, Bom> entry : vdrByAnalyzerName.entrySet()) {
            final String analyzerName = entry.getKey();
            final Bom vdr = entry.getValue();

            // Group components by their BOM ref for easier lookups later.
            final Map<String, org.cyclonedx.proto.v1_6.Component> componentByBomRef =
                    vdr.getComponentsList().stream()
                            .collect(Collectors.toMap(
                                    org.cyclonedx.proto.v1_6.Component::getBomRef,
                                    Function.identity()));

            for (final org.cyclonedx.proto.v1_6.Vulnerability vdrVuln : vdr.getVulnerabilitiesList()) {
                final Vulnerability vuln = ModelConverterCdxToVuln.convert(
                        /* qm */ null, vdr, vdrVuln, /* isAliasSyncEnabled */ false);

                reportedVulnsByVulnId.computeIfAbsent(vuln.getVulnId(), ignored -> new HashSet<>()).add(vuln);

                // Restore which components are affected by this vulnerability.
                for (final VulnerabilityAffects affects : vdrVuln.getAffectsList()) {
                    final org.cyclonedx.proto.v1_6.Component affectedComponent = componentByBomRef.get(affects.getRef());
                    if (affectedComponent == null) {
                        LOGGER.warn("No component found for BOM ref {}", affects.getRef());
                        continue;
                    }

                    final Long componentId = affectedComponent.getPropertiesList().stream()
                            .filter(property -> "internal:component-id".equals(property.getName()))
                            .map(Property::getValue)
                            .map(Long::parseLong)
                            .findFirst()
                            .orElse(null);
                    if (componentId == null) {
                        LOGGER.warn("No component ID found for component with BOM ref {}", affects.getRef());
                        continue;
                    }

                    final var findingId = new FindingId(componentId, vuln.getVulnId());
                    analyzersByReportedFindingId.computeIfAbsent(findingId, ignored -> new HashSet<>()).add(analyzerName);
                    vulnIdsByComponentId.computeIfAbsent(componentId, ignored -> new HashSet<>()).add(vuln.getVulnId());
                }
            }
        }

        // TODO: Filter out components that no longer exist?

        // TODO: Move to DAO class.
        // NB: Batch operations can lead to deadlocks here when multiple threads do it concurrently.
        final var vulnRecordByVulnId = new HashMap<String, Vulnerability>();
        final var vulnIdByVulnRecordId = new HashMap<Long, String>();
        for (final Map.Entry<String, Set<Vulnerability>> entry : reportedVulnsByVulnId.entrySet()) {
            // TODO: Pick the "best" among $vulns.
            final Vulnerability vuln = entry.getValue().iterator().next();

            final Vulnerability syncedVuln = syncVuln(vuln);
            vulnRecordByVulnId.put(syncedVuln.getVulnId(), syncedVuln);
            vulnIdByVulnRecordId.put(syncedVuln.getId(), syncedVuln.getVulnId());
        }

        LOGGER.debug("Created or updated {} vulns", vulnRecordByVulnId.size());

        final var matchedPolicyByVulnUuid = new HashMap<UUID, VulnerabilityPolicy>();

        if (vulnPolicyEvaluator != null) {
            final var policyProject =
                    org.dependencytrack.proto.policy.v1.Project.newBuilder()
                            .setUuid(args.getProject().getUuid())
                            .build();

            final Map<Long, UUID> componentUuidByComponentId = getComponentUuids(vulnIdsByComponentId.keySet());

            // TODO: Should evaluate once for the entire project,
            //  instead of for each component separately.

            for (final Map.Entry<Long, Set<String>> entry : vulnIdsByComponentId.entrySet()) {
                final Long componentId = entry.getKey();
                final Set<String> vulnIds = entry.getValue();

                final org.dependencytrack.proto.policy.v1.Component policyComponent =
                        org.dependencytrack.proto.policy.v1.Component.newBuilder()
                                .setUuid(componentUuidByComponentId.get(componentId).toString())
                                .build();

                final List<org.dependencytrack.proto.policy.v1.Vulnerability> policyVulns =
                        vulnIds.stream()
                                .map(vulnRecordByVulnId::get)
                                .map(PolicyProtoMapper::mapToProto)
                                .toList();

                matchedPolicyByVulnUuid.putAll(
                        vulnPolicyEvaluator.evaluate(policyVulns, policyComponent, policyProject));
            }
        }

        // NB: Processing findings cannot be done with DataNucleus.
        // In order to associate a component with a vulnerability, DN would need to
        // load *all* components already associated with the vulnerability into memory.

        useJdbiTransaction(handle -> {
            // Fetch all existing finding attributions for this project.
            // We need them to determine which findings to create, which to suppress, and which leave untouched.
            final Query attributionsQuery = handle.createQuery("""
                    SELECT "COMPONENT_ID"
                         , "VULNERABILITY_ID"
                         , "ANALYZERIDENTITY"
                         , "ATTRIBUTED_ON"
                      FROM "FINDINGATTRIBUTION"
                     WHERE "PROJECT_ID" = :projectId
                    """);

            final Map<FindingId, FindingAttribution> attributionByFindingId = attributionsQuery
                    .bind("projectId", projectId)
                    .map(ConstructorMapper.of(FindingAttribution.class))
                    .list()
                    .stream()
                    .collect(Collectors.toMap(
                            attribution -> new FindingId(
                                    attribution.componentId(),
                                    vulnIdByVulnRecordId.get(attribution.vulnerabilityId())),
                            Function.identity()));

            final var findingIds = new HashSet<FindingId>();
            findingIds.addAll(analyzersByReportedFindingId.keySet());
            findingIds.addAll(attributionByFindingId.keySet());

            final var analyzerByFindingIdToCreate = new HashMap<FindingId, String>();
            final var findingIdsToSuppress = new HashSet<FindingId>();

            for (final FindingId findingId : findingIds) {
                final Set<String> reportingAnalyzers = analyzersByReportedFindingId.get(findingId);
                final FindingAttribution existingAttribution = attributionByFindingId.get(findingId);

                if (reportingAnalyzers == null || reportingAnalyzers.isEmpty()) {
                    if (failedAnalyzers.contains(existingAttribution.analyzerIdentity())) {
                        LOGGER.warn("""
                                Finding {} was previously reported by {}, but is no longer reported \
                                by any analyzer; {} was failed its analysis, will not suppress\
                                """, findingId, existingAttribution.analyzerIdentity(), existingAttribution.analyzerIdentity());
                    } else {
                        LOGGER.info("""
                                Finding {} was reported by {} before, but no longer reported \
                                by any analyzer and will be suppressed""", findingId, existingAttribution.analyzerIdentity());
                        findingIdsToSuppress.add(findingId);
                    }
                } else if (existingAttribution == null) {
                    // TODO: Any better strategy than choosing the first alphabetically?
                    // TODO: Mid-term, *all* analyzers must be attributed, not just one.
                    final String analyzer = reportingAnalyzers.stream().sorted().findFirst().get();

                    LOGGER.debug("Finding {} was not reported before and will be attributed to {}", findingId, analyzer);
                    analyzerByFindingIdToCreate.put(findingId, analyzer);
                } else {
                    // TODO: Handle findings that were previously auto-suppressed but now reported again.

                    LOGGER.debug(
                            "Finding {} was reported before by {} and is still reported by {}",
                            findingId, existingAttribution.analyzerIdentity(), reportingAnalyzers);
                }
            }

            if (!analyzerByFindingIdToCreate.isEmpty()) {
                final var findingComponentIds = new ArrayList<Long>();
                final var findingVulnRecordIds = new ArrayList<Long>();
                final var analyzers = new ArrayList<String>();
                final var attributionUuids = new ArrayList<UUID>();

                for (final Map.Entry<FindingId, String> entry : analyzerByFindingIdToCreate.entrySet()) {
                    final FindingId findingId = entry.getKey();
                    final String analyzer = entry.getValue();

                    findingComponentIds.add(findingId.componentId());
                    findingVulnRecordIds.add(vulnRecordByVulnId.get(findingId.vulnId()).getId());
                    analyzers.add(analyzer);
                    attributionUuids.add(UUID.randomUUID());
                }

                final Update createFindingsQuery = handle.createUpdate("""
                        WITH
                        finding as (
                          SELECT *
                            FROM UNNEST(
                                   :componentIds
                                 , :vulnRecordIds
                                 , :analyzers
                                 , :attributionUuids
                                 ) AS t (
                                   component_id
                                 , vulnerability_id
                                 , analyzer
                                 , attribution_uuid
                                 )
                           ORDER BY component_id
                                  , vulnerability_id
                        ),
                        created_finding AS (
                          INSERT INTO "COMPONENTS_VULNERABILITIES" ("COMPONENT_ID", "VULNERABILITY_ID")
                          SELECT component_id
                               , vulnerability_id
                            FROM finding
                          ON CONFLICT ("COMPONENT_ID", "VULNERABILITY_ID") DO NOTHING
                          RETURNING "COMPONENT_ID", "VULNERABILITY_ID"
                        )
                        INSERT INTO "FINDINGATTRIBUTION" (
                          "PROJECT_ID"
                        , "COMPONENT_ID"
                        , "VULNERABILITY_ID"
                        , "ANALYZERIDENTITY"
                        , "ATTRIBUTED_ON"
                        , "UUID"
                        )
                        SELECT :projectId
                             , finding.component_id
                             , finding.vulnerability_id
                             , analyzer
                             , NOW()
                             , attribution_uuid
                          FROM finding
                         INNER JOIN created_finding
                            ON created_finding."COMPONENT_ID" = finding.component_id
                           AND created_finding."VULNERABILITY_ID" = finding.vulnerability_id
                        """);

                final int findingsCreated = createFindingsQuery
                        .bindArray("componentIds", Long.class, findingComponentIds)
                        .bindArray("vulnRecordIds", Long.class, findingVulnRecordIds)
                        .bindArray("analyzers", String.class, analyzers)
                        .bindArray("attributionUuids", UUID.class, attributionUuids)
                        .bind("projectId", projectId)
                        .execute();
                LOGGER.debug("Created {} findings", findingsCreated);
            }

            if (!findingIdsToSuppress.isEmpty()) {
                // TODO: We need a way to mark *why* a finding was suppressed.
                LOGGER.warn("Suppressing {}", findingIdsToSuppress);
            }
        });

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            for (final FileMetadata fileMetadata : resultsFileMetadataSet) {
                LOGGER.debug("Deleting VDR file {}", fileMetadata.getLocation());
                fileStorage.delete(fileMetadata);
            }
        }

        return Optional.empty();
    }

    private Long getProjectId(final Project project) {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "ID"
                     FROM "PROJECT"
                    WHERE "UUID" = CAST(:projectUuid AS UUID)
                    """);

            return query
                    .bind("projectUuid", project.getUuid())
                    .mapTo(Long.class)
                    .findOne()
                    .orElse(null);
        });
    }

    private Map<Long, UUID> getComponentUuids(final Collection<Long> componentIds) {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "ID"
                         , "UUID"
                      FROM "COMPONENT"
                     WHERE "ID" = ANY(:componentIds)
                    """);
            final List<Map<String, Object>> queryResult = query
                    .bindArray("componentIds", Long.class, componentIds)
                    .mapToMap()
                    .list();
            return queryResult.stream()
                    .collect(Collectors.toMap(
                            row -> (Long) row.get("id"),
                            row -> (UUID) row.get("uuid")));
        });
    }

    private Vulnerability syncVuln(final Vulnerability vuln) {
        try (final var qm = new QueryManager();
             var ignoredMdcVulnId = MDC.putCloseable("vulnId", vuln.getVulnId())) {
            qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            return qm.callInTransaction(() -> {
                LOGGER.debug("Acquiring write lock");
                qm.acquireAdvisoryLock("vuln:write:%s:%s".formatted(vuln.getSource(), vuln.getVulnId()));

                final org.dependencytrack.model.Vulnerability existingVuln;
                final javax.jdo.Query<Vulnerability> query = qm.getPersistenceManager().newQuery(Vulnerability.class);
                try {
                    query.setFilter("vulnId == :vulnId && source == :source");
                    query.setParameters(vuln.getVulnId(), vuln.getSource());
                    existingVuln = query.executeUnique();
                } finally {
                    query.closeAll();
                }

                if (existingVuln == null) {
                    if (org.dependencytrack.model.Vulnerability.Source.INTERNAL.name().equals(vuln.getSource())) {
                        throw new NoSuchElementException("An internal vulnerability with ID %s does not exist".formatted(vuln.getVulnId()));
                    }

                    LOGGER.debug("Vulnerability does not exist yet; Creating it");
                    return qm.persist(vuln);
                }

                if (/* canUpdateVulnerability(existingVuln, scanner) */ true) {
                    LOGGER.debug("Vulnerability exists; Updating if necessary");

                    final var differ = new PersistenceUtil.Differ<>(existingVuln, vuln);
                    differ.applyIfChanged("title", Vulnerability::getTitle, existingVuln::setTitle);
                    differ.applyIfChanged("subTitle", Vulnerability::getSubTitle, existingVuln::setSubTitle);
                    differ.applyIfChanged("description", Vulnerability::getDescription, existingVuln::setDescription);
                    differ.applyIfChanged("detail", Vulnerability::getDetail, existingVuln::setDetail);
                    differ.applyIfChanged("recommendation", Vulnerability::getRecommendation, existingVuln::setRecommendation);
                    differ.applyIfChanged("references", Vulnerability::getReferences, existingVuln::setReferences);
                    differ.applyIfChanged("credits", Vulnerability::getCredits, existingVuln::setCredits);
                    differ.applyIfChanged("created", Vulnerability::getCreated, existingVuln::setCreated);
                    differ.applyIfChanged("published", Vulnerability::getPublished, existingVuln::setPublished);
                    differ.applyIfChanged("updated", Vulnerability::getUpdated, existingVuln::setUpdated);
                    differ.applyIfChanged("cwes", Vulnerability::getCwes, existingVuln::setCwes);
                    differ.applyIfChanged("severity", Vulnerability::getSeverity, existingVuln::setSeverity);
                    differ.applyIfChanged("cvssV2BaseScore", Vulnerability::getCvssV2BaseScore, existingVuln::setCvssV2BaseScore);
                    differ.applyIfChanged("cvssV2ImpactSubScore", Vulnerability::getCvssV2ImpactSubScore, existingVuln::setCvssV2ImpactSubScore);
                    differ.applyIfChanged("cvssV2ExploitabilitySubScore", Vulnerability::getCvssV2ExploitabilitySubScore, existingVuln::setCvssV2ExploitabilitySubScore);
                    differ.applyIfChanged("cvssV2Vector", Vulnerability::getCvssV2Vector, existingVuln::setCvssV2Vector);
                    differ.applyIfChanged("cvssv3BaseScore", Vulnerability::getCvssV3BaseScore, existingVuln::setCvssV3BaseScore);
                    differ.applyIfChanged("cvssV3ImpactSubScore", Vulnerability::getCvssV3ImpactSubScore, existingVuln::setCvssV3ImpactSubScore);
                    differ.applyIfChanged("cvssV3ExploitabilitySubScore", Vulnerability::getCvssV3ExploitabilitySubScore, existingVuln::setCvssV3ExploitabilitySubScore);
                    differ.applyIfChanged("cvssV3Vector", Vulnerability::getCvssV3Vector, existingVuln::setCvssV3Vector);
                    differ.applyIfChanged("owaspRRLikelihoodScore", Vulnerability::getOwaspRRLikelihoodScore, existingVuln::setOwaspRRLikelihoodScore);
                    differ.applyIfChanged("owaspRRTechnicalImpactScore", Vulnerability::getOwaspRRTechnicalImpactScore, existingVuln::setOwaspRRTechnicalImpactScore);
                    differ.applyIfChanged("owaspRRBusinessImpactScore", Vulnerability::getOwaspRRBusinessImpactScore, existingVuln::setOwaspRRBusinessImpactScore);
                    differ.applyIfChanged("owaspRRVector", Vulnerability::getOwaspRRVector, existingVuln::setOwaspRRVector);
                    // Aliases of existingVuln will always be null, as they'd have to be fetched separately.
                    // Synchronization of aliases is performed after synchronizing the vulnerability.
                    // updated |= applyIfChanged(existingVuln, vuln, Vulnerability::getAliases, existingVuln::setAliases);

                    differ.applyIfChanged("vulnerableVersions", Vulnerability::getVulnerableVersions, existingVuln::setVulnerableVersions);
                    differ.applyIfChanged("patchedVersions", Vulnerability::getPatchedVersions, existingVuln::setPatchedVersions);

                    if (!differ.getDiffs().isEmpty() && LOGGER.isDebugEnabled()) {
                        // TODO: Notification.
                        LOGGER.debug("Vulnerability changed: {}", differ.getDiffs());
                    }
                }

                return existingVuln;
            });
        }
    }

}
