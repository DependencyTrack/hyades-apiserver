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

import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.parser.dependencytrack.ModelConverterCdxToVuln;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectVulnAnalysisResultsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.Project;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.framework.ActivityClient;
import org.dependencytrack.workflow.framework.ActivityContext;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Activity(name = "process-project-vuln-analysis-results")
public class ProcessProjectVulnAnalysisResultsActivity implements ActivityExecutor<ProcessProjectVulnAnalysisResultsArgs, Void> {

    public static final ActivityClient<ProcessProjectVulnAnalysisResultsArgs, Void> CLIENT = ActivityClient.of(
            ProcessProjectVulnAnalysisResultsActivity.class,
            protoConverter(ProcessProjectVulnAnalysisResultsArgs.class),
            voidConverter());

    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessProjectVulnAnalysisResultsActivity.class);

    @Override
    public Optional<Void> execute(final ActivityContext<ProcessProjectVulnAnalysisResultsArgs> ctx) throws Exception {
        final ProcessProjectVulnAnalysisResultsArgs args = ctx.argument().orElseThrow();

        final Long projectId = getProjectId(args.getProject());
        if (projectId == null) {
            throw new ApplicationFailureException("Project with UUID %s does not exist".formatted(
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

        final var vulnsById = new HashMap<String, Set<org.dependencytrack.model.Vulnerability>>();
        final var vulnIdsByComponentId = new HashMap<Long, Set<String>>();

        for (final Map.Entry<String, Bom> entry : vdrByAnalyzerName.entrySet()) {
            final String analyzerName = entry.getKey();
            final Bom vdr = entry.getValue();

            // Group components by their BOM ref for easier lookups later.
            final Map<String, Component> componentByBomRef = vdr.getComponentsList().stream()
                    .collect(Collectors.toMap(Component::getBomRef, Function.identity()));

            for (final Vulnerability vdrVuln : vdr.getVulnerabilitiesList()) {
                final org.dependencytrack.model.Vulnerability vuln = ModelConverterCdxToVuln.convert(
                        /* qm */ null, vdr, vdrVuln, /* isAliasSyncEnabled */ false);

                vulnsById.computeIfAbsent(vuln.getVulnId(), ignored -> new HashSet<>()).add(vuln);

                // Restore which components are affected by this vulnerability.
                for (final VulnerabilityAffects affects : vdrVuln.getAffectsList()) {
                    final Component affectedComponent = componentByBomRef.get(affects.getRef());
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

                    vulnIdsByComponentId.computeIfAbsent(componentId, ignored -> new HashSet<>()).add(vuln.getVulnId());
                }
            }
        }

        // TODO: Filter out components that no longer exist?

        // TODO: Move to DAO class.
        // NB: Batch operations can lead to deadlocks here when multiple threads do it concurrently.
        final var vulnRecordIdByVulnId = new HashMap<String, Long>();
        for (final Map.Entry<String, Set<org.dependencytrack.model.Vulnerability>> entry : vulnsById.entrySet()) {
            // TODO: Pick the "best" among $vulns.
            final org.dependencytrack.model.Vulnerability vuln = entry.getValue().iterator().next();

            try (final var qm = new QueryManager();
                 var ignoredMdcVulnId = MDC.putCloseable("vulnId", vuln.getVulnId())) {
                qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());
                qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

                final org.dependencytrack.model.Vulnerability persistentVuln = qm.callInTransaction(() -> {
                    LOGGER.debug("Acquiring write lock");
                    qm.acquireAdvisoryLock("vuln:write:%s:%s".formatted(vuln.getSource(), vuln.getVulnId()));

                    final org.dependencytrack.model.Vulnerability existingVuln;
                    final javax.jdo.Query<org.dependencytrack.model.Vulnerability> query = qm.getPersistenceManager().newQuery(org.dependencytrack.model.Vulnerability.class);
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
                        differ.applyIfChanged("title", org.dependencytrack.model.Vulnerability::getTitle, existingVuln::setTitle);
                        differ.applyIfChanged("subTitle", org.dependencytrack.model.Vulnerability::getSubTitle, existingVuln::setSubTitle);
                        differ.applyIfChanged("description", org.dependencytrack.model.Vulnerability::getDescription, existingVuln::setDescription);
                        differ.applyIfChanged("detail", org.dependencytrack.model.Vulnerability::getDetail, existingVuln::setDetail);
                        differ.applyIfChanged("recommendation", org.dependencytrack.model.Vulnerability::getRecommendation, existingVuln::setRecommendation);
                        differ.applyIfChanged("references", org.dependencytrack.model.Vulnerability::getReferences, existingVuln::setReferences);
                        differ.applyIfChanged("credits", org.dependencytrack.model.Vulnerability::getCredits, existingVuln::setCredits);
                        differ.applyIfChanged("created", org.dependencytrack.model.Vulnerability::getCreated, existingVuln::setCreated);
                        differ.applyIfChanged("published", org.dependencytrack.model.Vulnerability::getPublished, existingVuln::setPublished);
                        differ.applyIfChanged("updated", org.dependencytrack.model.Vulnerability::getUpdated, existingVuln::setUpdated);
                        differ.applyIfChanged("cwes", org.dependencytrack.model.Vulnerability::getCwes, existingVuln::setCwes);
                        differ.applyIfChanged("severity", org.dependencytrack.model.Vulnerability::getSeverity, existingVuln::setSeverity);
                        differ.applyIfChanged("cvssV2BaseScore", org.dependencytrack.model.Vulnerability::getCvssV2BaseScore, existingVuln::setCvssV2BaseScore);
                        differ.applyIfChanged("cvssV2ImpactSubScore", org.dependencytrack.model.Vulnerability::getCvssV2ImpactSubScore, existingVuln::setCvssV2ImpactSubScore);
                        differ.applyIfChanged("cvssV2ExploitabilitySubScore", org.dependencytrack.model.Vulnerability::getCvssV2ExploitabilitySubScore, existingVuln::setCvssV2ExploitabilitySubScore);
                        differ.applyIfChanged("cvssV2Vector", org.dependencytrack.model.Vulnerability::getCvssV2Vector, existingVuln::setCvssV2Vector);
                        differ.applyIfChanged("cvssv3BaseScore", org.dependencytrack.model.Vulnerability::getCvssV3BaseScore, existingVuln::setCvssV3BaseScore);
                        differ.applyIfChanged("cvssV3ImpactSubScore", org.dependencytrack.model.Vulnerability::getCvssV3ImpactSubScore, existingVuln::setCvssV3ImpactSubScore);
                        differ.applyIfChanged("cvssV3ExploitabilitySubScore", org.dependencytrack.model.Vulnerability::getCvssV3ExploitabilitySubScore, existingVuln::setCvssV3ExploitabilitySubScore);
                        differ.applyIfChanged("cvssV3Vector", org.dependencytrack.model.Vulnerability::getCvssV3Vector, existingVuln::setCvssV3Vector);
                        differ.applyIfChanged("owaspRRLikelihoodScore", org.dependencytrack.model.Vulnerability::getOwaspRRLikelihoodScore, existingVuln::setOwaspRRLikelihoodScore);
                        differ.applyIfChanged("owaspRRTechnicalImpactScore", org.dependencytrack.model.Vulnerability::getOwaspRRTechnicalImpactScore, existingVuln::setOwaspRRTechnicalImpactScore);
                        differ.applyIfChanged("owaspRRBusinessImpactScore", org.dependencytrack.model.Vulnerability::getOwaspRRBusinessImpactScore, existingVuln::setOwaspRRBusinessImpactScore);
                        differ.applyIfChanged("owaspRRVector", org.dependencytrack.model.Vulnerability::getOwaspRRVector, existingVuln::setOwaspRRVector);
                        // Aliases of existingVuln will always be null, as they'd have to be fetched separately.
                        // Synchronization of aliases is performed after synchronizing the vulnerability.
                        // updated |= applyIfChanged(existingVuln, vuln, Vulnerability::getAliases, existingVuln::setAliases);

                        differ.applyIfChanged("vulnerableVersions", org.dependencytrack.model.Vulnerability::getVulnerableVersions, existingVuln::setVulnerableVersions);
                        differ.applyIfChanged("patchedVersions", org.dependencytrack.model.Vulnerability::getPatchedVersions, existingVuln::setPatchedVersions);

                        if (!differ.getDiffs().isEmpty() && LOGGER.isDebugEnabled()) {
                            LOGGER.debug("Vulnerability changed: {}", differ.getDiffs());
                        }
                    }

                    return existingVuln;
                });

                vulnRecordIdByVulnId.put(entry.getKey(), persistentVuln.getId());
            }
        }

        LOGGER.debug("Created or updated {} vulns", vulnRecordIdByVulnId.size());

        final int createdFindingsCount = inJdbiTransaction(handle -> {
            final var componentIds = new ArrayList<Long>();
            final var vulnRecordIds = new ArrayList<Long>();

            for (final Map.Entry<Long, Set<String>> entry : vulnIdsByComponentId.entrySet()) {
                for (final String vulnId : entry.getValue()) {
                    componentIds.add(entry.getKey());
                    vulnRecordIds.add(vulnRecordIdByVulnId.get(vulnId));
                }
            }

            final Update createFindingsQuery = handle.createUpdate("""
                    INSERT INTO "COMPONENTS_VULNERABILITIES"("COMPONENT_ID", "VULNERABILITY_ID")
                    SELECT * FROM UNNEST(:componentIds, :vulnRecordIds) ORDER BY 1, 2
                    ON CONFLICT("COMPONENT_ID", "VULNERABILITY_ID") DO NOTHING
                    RETURNING "COMPONENT_ID", "VULNERABILITY_ID"
                    """);

            final List<Map<String, Long>> createdFindings = createFindingsQuery
                    .bindArray("componentIds", Long.class, componentIds)
                    .bindArray("vulnRecordIds", Long.class, vulnRecordIds)
                    .executeAndReturnGeneratedKeys()
                    .mapToMap(Long.class)
                    .list();
            if (createdFindings.isEmpty()) {
                return 0;
            }

            final var attributionComponentIds = new ArrayList<Long>(createdFindings.size());
            final var attributionVulnRecordIds = new ArrayList<Long>(createdFindings.size());
            final var attributionUuids = new ArrayList<UUID>(createdFindings.size());
            for (final Map<String, Long> createdFinding : createdFindings) {
                attributionComponentIds.add(createdFinding.get("component_id"));
                attributionVulnRecordIds.add(createdFinding.get("vulnerability_id"));
                attributionUuids.add(UUID.randomUUID());
            }

            final Update createAttributionsQuery = handle.createUpdate("""
                    INSERT INTO "FINDINGATTRIBUTION" (
                      "PROJECT_ID"
                    , "COMPONENT_ID"
                    , "VULNERABILITY_ID"
                    , "ANALYZERIDENTITY"
                    , "ATTRIBUTED_ON"
                    , "UUID"
                    )
                    SELECT :projectId
                         , "COMPONENT_ID"
                         , "VULNERABILITY_ID"
                         , 'INTERNAL_ANALYZER'
                         , NOW()
                         , "UUID"
                      FROM UNNEST(:componentIds, :vulnRecordIds, :uuids) AS t("COMPONENT_ID", "VULNERABILITY_ID", "UUID") ORDER BY 1, 2
                    ON CONFLICT ("COMPONENT_ID", "VULNERABILITY_ID") DO NOTHING
                    """);

            final int createdAttributions = createAttributionsQuery
                    .bindArray("componentIds", Long.class, attributionComponentIds)
                    .bindArray("vulnRecordIds", Long.class, attributionVulnRecordIds)
                    .bindArray("uuids", UUID.class, attributionUuids)
                    .bind("projectId", projectId)
                    .execute();

            return createdFindings.size();
        });

        LOGGER.debug("Created {} findings", createdFindingsCount);

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

}
