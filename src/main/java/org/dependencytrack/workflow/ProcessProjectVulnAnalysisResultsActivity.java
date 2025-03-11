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
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectVulnAnalysisResultsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.Project;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ActivityClient;
import org.dependencytrack.workflow.framework.ActivityContext;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Activity(name = "process-project-analysis-results")
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

            final Map<String, Component> componentByBomRef = vdr.getComponentsList().stream()
                    .collect(Collectors.toMap(Component::getBomRef, Function.identity()));

            for (final Vulnerability vdrVuln : vdr.getVulnerabilitiesList()) {
                // TODO: Add mappings for all other vulnerability fields.
                final var vuln = new org.dependencytrack.model.Vulnerability();
                vuln.setVulnId(vdrVuln.getId());
                vuln.setSource(vdrVuln.getSource().getName());
                vulnsById.computeIfAbsent(vuln.getVulnId(), ignored -> new HashSet<>()).add(vuln);

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
            final org.dependencytrack.model.Vulnerability vuln = entry.getValue().iterator().next();

            // TODO: Pick the "best" among $vulns.

            final long vulnRecordId = inJdbiTransaction(handle -> {
                acquireAdvisoryLockForVuln(handle, vuln.getVulnId());

                // TODO: Fetch entire vuln record, compare, and update if necessary.
                final Query vulnQuery = handle.createQuery("""
                        SELECT "ID"
                          FROM "VULNERABILITY"
                         WHERE "VULNID" = :vulnId
                           AND "SOURCE" = :source
                        """);

                final Long id = vulnQuery
                        .bind("vulnId", vuln.getVulnId())
                        .bind("source", vuln.getSource())
                        .mapTo(Long.class)
                        .findOne()
                        .orElse(null);
                if (id != null) {
                    return id;
                }

                final Update update = handle.createUpdate("""
                        INSERT INTO "VULNERABILITY"("VULNID", "SOURCE", "UUID")
                        VALUES (:vulnId, :source, :uuid)
                        RETURNING "ID"
                        """);

                return update
                        .bind("vulnId", vuln.getVulnId())
                        .bind("source", vuln.getSource())
                        .bind("uuid", UUID.randomUUID())
                        .executeAndReturnGeneratedKeys()
                        .mapTo(Long.class)
                        .one();
            });

            vulnRecordIdByVulnId.put(entry.getKey(), vulnRecordId);
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

    private void acquireAdvisoryLockForVuln(final Handle jdbiHandle, final String vulnId) {
        if (!jdbiHandle.isInTransaction()) {
            throw new IllegalStateException();
        }

        jdbiHandle
                .createUpdate("SELECT PG_ADVISORY_XACT_LOCK(:lockId)")
                .setQueryTimeout(30 /* seconds */)
                .bind("lockId", "%s::%s".formatted(getClass().getName(), vulnId).hashCode())
                .execute();
    }

}
