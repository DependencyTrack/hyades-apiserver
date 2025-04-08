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
package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.cel.mapping.ComponentProjection;
import org.dependencytrack.policy.cel.mapping.ComponentsVulnerabilitiesProjection;
import org.dependencytrack.policy.cel.mapping.LicenseGroupProjection;
import org.dependencytrack.policy.cel.mapping.LicenseProjection;
import org.dependencytrack.policy.cel.mapping.PolicyViolationProjection;
import org.dependencytrack.policy.cel.mapping.ProjectProjection;
import org.dependencytrack.policy.cel.mapping.ProjectPropertyProjection;
import org.dependencytrack.policy.cel.mapping.VulnerabilityProjection;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.datastore.JDOConnection;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.sql.Connection.TRANSACTION_READ_COMMITTED;
import static org.dependencytrack.policy.cel.mapping.FieldMappingUtil.getFieldMappings;

class CelPolicyQueryManager implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyQueryManager.class);

    private final PersistenceManager pm;

    CelPolicyQueryManager(final QueryManager qm) {
        this.pm = qm.getPersistenceManager();
    }

    UUID getProjectUuidForComponentUuid(final UUID componentUuid) {
        try (final var qm = new QueryManager()) {
            final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class);
            query.setFilter("uuid == :uuid");
            query.setParameters(componentUuid);
            query.setResult("project.uuid");
            try {
                return query.executeResultUnique(UUID.class);
            } finally {
                query.closeAll();
            }
        }
    }

    ProjectProjection fetchProject(final long projectId,
                                   final Collection<String> projectProtoFieldNames,
                                   final Collection<String> projectPropertyProtoFieldNames) {
        // Determine the columns to select from the PROJECT (P) table.
        String sqlProjectSelectColumns = Stream.concat(
                        Stream.of(ProjectProjection.ID_FIELD_MAPPING),
                        getFieldMappings(ProjectProjection.class).stream()
                                .filter(mapping -> projectProtoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"P\".\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));

        // Determine the columns to select from the PROJECT_PROPERTY (PP) table.
        // The resulting expression will be used to populate JSON objects, using
        // the JSONB_BUILD_OBJECT(name1, value1, name2, value2) notation.
        String sqlPropertySelectColumns = "";
        if (projectPropertyProtoFieldNames != null) {
            sqlPropertySelectColumns = getFieldMappings(ProjectPropertyProjection.class).stream()
                    .filter(mapping -> projectPropertyProtoFieldNames.contains(mapping.protoFieldName()))
                    .map(mapping -> "'%s', \"PP\".\"%s\"".formatted(mapping.javaFieldName(), mapping.sqlColumnName()))
                    .collect(Collectors.joining(", "));
        }

        // Properties will be selected into propertiesJson, tags into tagsJson.
        // Both these fields are not part of the Project proto, thus their selection
        // must be added manually.
        if (!sqlPropertySelectColumns.isBlank()) {
            sqlProjectSelectColumns += ", \"propertiesJson\"";
        }
        if (projectProtoFieldNames.contains("tags")) {
            sqlProjectSelectColumns += ", \"tagsJson\"";
        }

        final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT
                  %s
                FROM
                  "PROJECT" AS "P"
                LEFT JOIN LATERAL (
                  SELECT
                    CAST(JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(%s)) AS TEXT) AS "propertiesJson"
                  FROM
                    "PROJECT_PROPERTY" AS "PP"
                  WHERE
                    "PP"."PROJECT_ID" = "P"."ID"
                ) AS "properties" ON :shouldFetchProperties
                LEFT JOIN LATERAL (
                  SELECT
                    CAST(JSONB_AGG(DISTINCT "T"."NAME") AS TEXT) AS "tagsJson"
                  FROM
                    "TAG" AS "T"
                  INNER JOIN
                    "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
                  WHERE
                    "PT"."PROJECT_ID" = "P"."ID"
                ) AS "tags" ON :shouldFetchTags
                WHERE
                  "ID" = :projectId
                """.formatted(sqlProjectSelectColumns, sqlPropertySelectColumns));
        query.setNamedParameters(Map.of(
                "shouldFetchProperties", !sqlPropertySelectColumns.isBlank(),
                "shouldFetchTags", projectProtoFieldNames.contains("tags"),
                "projectId", projectId
        ));
        try {
            return query.executeResultUnique(ProjectProjection.class);
        } finally {
            query.closeAll();
        }
    }

    List<ComponentProjection> fetchAllComponents(final long projectId, final Collection<String> protoFieldNames) {
        String sqlSelectColumns = Stream.concat(
                        Stream.of(ComponentProjection.ID_FIELD_MAPPING),
                        getFieldMappings(ComponentProjection.class).stream()
                                .filter(mapping -> protoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"C\".\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));
        if (protoFieldNames.contains("published_at")) {
            sqlSelectColumns += ", \"publishedAt\"";
        }
        if (protoFieldNames.contains("latest_version")) {
            sqlSelectColumns += ", \"latestVersion\"";
        }
        final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT %s, "latestVersion", "publishedAt"
                from
                "COMPONENT" "C"
                LEFT JOIN LATERAL (SELECT "IMC"."PUBLISHED_AT" AS "publishedAt" FROM "INTEGRITY_META_COMPONENT" "IMC" WHERE
                "C"."PURL" = "IMC"."PURL") AS "publishedAt" ON :shouldJoinIntegrityMeta
                LEFT JOIN LATERAL (SELECT "RMC"."LATEST_VERSION" AS "latestVersion" FROM "REPOSITORY_META_COMPONENT" "RMC" WHERE
                "C"."NAME" = "RMC"."NAME") AS "latestVersion" ON :shouldJoinRepoMeta
                WHERE
                "PROJECT_ID" = :projectId
                """.formatted(sqlSelectColumns, protoFieldNames));
        query.setNamedParameters(Map.of(
                "shouldJoinIntegrityMeta", protoFieldNames.contains("publishedAt") || protoFieldNames.contains("published_at"),
                "shouldJoinRepoMeta", protoFieldNames.contains("latestVersion") || protoFieldNames.contains("latest_version"),
                "projectId", projectId));
        try {
            return List.copyOf(query.executeResultList(ComponentProjection.class));
        } finally {
            query.closeAll();
        }
    }

    /**
     * Fetch all {@link org.dependencytrack.model.Component} {@code <->} {@link org.dependencytrack.model.Vulnerability}
     * relationships for a given {@link Project}.
     *
     * @param projectId ID of the {@link Project} to fetch relationships for
     * @return A {@link List} of {@link ComponentsVulnerabilitiesProjection}
     */
    List<ComponentsVulnerabilitiesProjection> fetchAllComponentsVulnerabilities(final long projectId) {
        final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT
                  "CV"."COMPONENT_ID" AS "componentId",
                  "CV"."VULNERABILITY_ID" AS "vulnerabilityId"
                FROM
                  "COMPONENTS_VULNERABILITIES" AS "CV"
                INNER JOIN
                  "COMPONENT" AS "C" ON "C"."ID" = "CV"."COMPONENT_ID"
                WHERE
                  "C"."PROJECT_ID" = ?
                """);
        query.setParameters(projectId);
        try {
            return List.copyOf(query.executeResultList(ComponentsVulnerabilitiesProjection.class));
        } finally {
            query.closeAll();
        }
    }

    List<LicenseProjection> fetchAllLicenses(final long projectId,
                                             final Collection<String> licenseProtoFieldNames,
                                             final Collection<String> licenseGroupProtoFieldNames) {
        final String licenseSqlSelectColumns = Stream.concat(
                        Stream.of(LicenseProjection.ID_FIELD_MAPPING),
                        getFieldMappings(LicenseProjection.class).stream()
                                .filter(mapping -> licenseProtoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"L\".\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));

        // If fetching license groups is not necessary, we can just query for licenses and be done with it.
        if (!licenseProtoFieldNames.contains("groups")) {
            final Query<?> query = pm.newQuery(Query.SQL, """
                    SELECT DISTINCT
                      %s
                    FROM
                      "LICENSE" AS "L"
                    INNER JOIN
                      "COMPONENT" AS "C" ON "C"."LICENSE_ID" = "L"."ID"
                    WHERE
                      "C"."PROJECT_ID" = ?
                    """.formatted(licenseSqlSelectColumns));
            query.setParameters(projectId);
            try {
                return List.copyOf(query.executeResultList(LicenseProjection.class));
            } finally {
                query.closeAll();
            }
        }

        // If groups are required, include them in the license query in order to avoid the 1+N problem.
        // Licenses may or may not be assigned to a group. Licenses can be in multiple groups.
        //
        // Using a simple LEFT JOIN would result in duplicate license data being fetched, e.g.:
        //
        // | "L"."ID" | "L"."NAME" | "LG"."NAME" |
        // | :------- | :--------- | :---------- |
        // | 1        | foo        | groupA      |
        // | 1        | foo        | groupB      |
        // | 1        | foo        | groupC      |
        // | 2        | bar        | NULL        |
        //
        // To avoid this, we instead aggregate license group fields for each license, and return them as JSON.
        // The reason for choosing JSON over native arrays, is that DataNucleus can't deal with arrays cleanly.
        //
        // | "L"."ID" | "L"."NAME" | "licenseGroupsJson"                                     |
        // | :------- | :--------- | :------------------------------------------------------ |
        // | 1        | foo        | [{"name":"groupA"},{"name":"groupB"},{"name":"groupC"}] |
        // | 2        | bar        | []                                                      |

        final String licenseSqlGroupByColumns = Stream.concat(
                        Stream.of(LicenseProjection.ID_FIELD_MAPPING),
                        getFieldMappings(LicenseProjection.class).stream()
                                .filter(mapping -> licenseProtoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"L\".\"%s\"".formatted(mapping.sqlColumnName()))
                .collect(Collectors.joining(", "));

        final String licenseGroupSqlSelectColumns = getFieldMappings(LicenseGroupProjection.class).stream()
                .filter(mapping -> licenseGroupProtoFieldNames.contains(mapping.protoFieldName()))
                .map(mapping -> "'%s', \"LG\".\"%s\"".formatted(mapping.javaFieldName(), mapping.sqlColumnName()))
                .collect(Collectors.joining(", "));

        final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT DISTINCT
                  "L"."ID" AS "id",
                  %s,
                  CAST(JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(%s)) AS TEXT) AS "licenseGroupsJson"
                FROM
                  "LICENSE" AS "L"
                INNER JOIN
                  "COMPONENT" AS "C" ON "C"."LICENSE_ID" = "L"."ID"
                LEFT JOIN
                  "LICENSEGROUP_LICENSE" AS "LGL" ON "LGL"."LICENSE_ID" = "L"."ID"
                LEFT JOIN
                  "LICENSEGROUP" AS "LG" ON "LG"."ID" = "LGL"."LICENSEGROUP_ID"
                WHERE
                  "C"."PROJECT_ID" = ?
                GROUP BY
                  %s
                """.formatted(licenseSqlSelectColumns, licenseGroupSqlSelectColumns, licenseSqlGroupByColumns));
        query.setParameters(projectId);
        try {
            return List.copyOf(query.executeResultList(LicenseProjection.class));
        } finally {
            query.closeAll();
        }
    }

    List<VulnerabilityProjection> fetchAllVulnerabilities(final long projectId, final Collection<String> protoFieldNames) {
        String sqlSelectColumns = Stream.concat(
                        Stream.of(VulnerabilityProjection.ID_FIELD_MAPPING),
                        getFieldMappings(VulnerabilityProjection.class).stream()
                                .filter(mapping -> protoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"V\".\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));

        if (protoFieldNames.contains("aliases")) {
            sqlSelectColumns += ", \"aliasesJson\"";
        }
        if (protoFieldNames.contains("epss_score")) {
            sqlSelectColumns += ", \"EP\".\"SCORE\" AS \"epssScore\"";
        }
        if (protoFieldNames.contains("epss_percentile")) {
            sqlSelectColumns += ", \"EP\".\"PERCENTILE\" AS \"epssPercentile\"";
        }

        final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT DISTINCT
                  %s
                FROM
                  "VULNERABILITY" AS "V"
                INNER JOIN
                  "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."VULNERABILITY_ID" = "V"."ID"
                INNER JOIN
                  "COMPONENT" AS "C" ON "C"."ID" = "CV"."COMPONENT_ID"
                LEFT JOIN LATERAL (
                  SELECT
                    CAST(JSONB_AGG(DISTINCT JSONB_STRIP_NULLS(JSONB_BUILD_OBJECT(
                      'cveId',      "VA"."CVE_ID",
                      'ghsaId',     "VA"."GHSA_ID",
                      'gsdId',      "VA"."GSD_ID",
                      'internalId', "VA"."INTERNAL_ID",
                      'osvId',      "VA"."OSV_ID",
                      'sonatypeId', "VA"."SONATYPE_ID",
                      'snykId',     "VA"."SNYK_ID",
                      'vulnDbId',   "VA"."VULNDB_ID"
                    ))) AS TEXT) AS "aliasesJson"
                  FROM
                    "VULNERABILITYALIAS" AS "VA"
                  WHERE
                    ("V"."SOURCE" = 'NVD' AND "VA"."CVE_ID" = "V"."VULNID")
                      OR ("V"."SOURCE" = 'GITHUB' AND "VA"."GHSA_ID" = "V"."VULNID")
                      OR ("V"."SOURCE" = 'GSD' AND "VA"."GSD_ID" = "V"."VULNID")
                      OR ("V"."SOURCE" = 'INTERNAL' AND "VA"."INTERNAL_ID" = "V"."VULNID")
                      OR ("V"."SOURCE" = 'OSV' AND "VA"."OSV_ID" = "V"."VULNID")
                      OR ("V"."SOURCE" = 'SONATYPE' AND "VA"."SONATYPE_ID" = "V"."VULNID")
                      OR ("V"."SOURCE" = 'SNYK' AND "VA"."SNYK_ID" = "V"."VULNID")
                      OR ("V"."SOURCE" = 'VULNDB' AND "VA"."VULNDB_ID" = "V"."VULNID")
                ) AS "aliases" ON :shouldFetchAliases
                LEFT JOIN "EPSS" AS "EP" ON "V"."VULNID" = "EP"."CVE" AND :shouldFetchEpss
                WHERE
                  "C"."PROJECT_ID" = :projectId
                """.formatted(sqlSelectColumns));
        query.setNamedParameters(Map.of(
                "shouldFetchAliases", protoFieldNames.contains("aliases"),
                "projectId", projectId,
                "shouldFetchEpss", protoFieldNames.contains("epss_score") || protoFieldNames.contains("epss_percentile")
        ));
        try {
            return List.copyOf(query.executeResultList(VulnerabilityProjection.class));
        } finally {
            query.closeAll();
        }
    }

    List<Long> reconcileViolations(final long projectId, final MultiValuedMap<Long, PolicyViolation> reportedViolationsByComponentId) {
        // We want to send notifications for newly identified policy violations,
        // so need to keep track of which violations we created.
        final var newViolationIds = new ArrayList<Long>();

        // DataNucleus does not support batch inserts, which is something we need in order to
        // create new violations efficiently. Falling back to "raw" JDBC for the sake of efficiency.
        final JDOConnection jdoConnection = pm.getDataStoreConnection();
        final var nativeConnection = (Connection) jdoConnection.getNativeConnection();
        Boolean originalAutoCommit = null;
        Integer originalTrxIsolation = null;

        try {
            // JDBC connections default to autocommit.
            // We'll do multiple write operations here, and want to commit them all in a single transaction.
            originalAutoCommit = nativeConnection.getAutoCommit();
            originalTrxIsolation = nativeConnection.getTransactionIsolation();
            nativeConnection.setAutoCommit(false);
            nativeConnection.setTransactionIsolation(TRANSACTION_READ_COMMITTED);

            // First, query for all existing policy violations of the project, grouping them by component ID.
            final var existingViolationsByComponentId = new HashSetValuedHashMap<Long, PolicyViolationProjection>();
            try (final PreparedStatement ps = nativeConnection.prepareStatement("""
                    SELECT
                      "ID"                 AS "id",
                      "COMPONENT_ID"       AS "componentId",
                      "POLICYCONDITION_ID" AS "policyConditionId"
                    FROM
                      "POLICYVIOLATION"
                    WHERE
                      "PROJECT_ID" = ?
                    """)) {
                ps.setLong(1, projectId);

                final ResultSet rs = ps.executeQuery();
                while (rs.next()) {
                    existingViolationsByComponentId.put(
                            rs.getLong("componentId"),
                            new PolicyViolationProjection(
                                    rs.getLong("id"),
                                    rs.getLong("policyConditionId")
                            ));
                }
            }

            // For each component that has existing and / or reported violations...
            final Set<Long> componentIds = new HashSet<>(reportedViolationsByComponentId.keySet().size() + existingViolationsByComponentId.keySet().size());
            componentIds.addAll(reportedViolationsByComponentId.keySet());
            componentIds.addAll(existingViolationsByComponentId.keySet());

            // ... determine which existing violations should be deleted (because they're no longer reported),
            // and which reported violations should be created (because they have not been reported before).
            //
            // Violations not belonging to either of those buckets are reported, but already exist,
            // meaning no action needs to be taken for them.
            final var violationIdsToDelete = new ArrayList<Long>();
            final var violationsToCreate = new HashSetValuedHashMap<Long, PolicyViolation>();
            for (final Long componentId : componentIds) {
                final Collection<PolicyViolationProjection> existingViolations = existingViolationsByComponentId.get(componentId);
                final Collection<PolicyViolation> reportedViolations = reportedViolationsByComponentId.get(componentId);

                if (reportedViolations == null || reportedViolations.isEmpty()) {
                    // Component has been removed, or does not have any violations anymore.
                    // All of its existing violations can be deleted.
                    violationIdsToDelete.addAll(existingViolations.stream().map(PolicyViolationProjection::id).toList());
                    continue;
                }

                if (existingViolations == null || existingViolations.isEmpty()) {
                    // Component did not have any violations before, but has some now.
                    // All reported violations must be newly created.
                    violationsToCreate.putAll(componentId, reportedViolations);
                    continue;
                }

                // To determine which violations shall be deleted, find occurrences of violations appearing
                // in the collection of existing violations, but not in the collection of reported violations.
                existingViolations.stream()
                        .filter(existingViolation -> reportedViolations.stream().noneMatch(newViolation ->
                                newViolation.getPolicyCondition().getId() == existingViolation.policyConditionId()))
                        .map(PolicyViolationProjection::id)
                        .forEach(violationIdsToDelete::add);

                // To determine which violations shall be created, find occurrences of violations appearing
                // in the collection of reported violations, but not in the collection of existing violations.
                reportedViolations.stream()
                        .filter(reportedViolation -> existingViolations.stream().noneMatch(existingViolation ->
                                existingViolation.policyConditionId() == reportedViolation.getPolicyCondition().getId()))
                        .forEach(reportedViolation -> violationsToCreate.put(componentId, reportedViolation));
            }

            if (!violationsToCreate.isEmpty()) {
                // For violations that need to be created, utilize batch inserts to limit database round-trips.
                // Keep note of the IDs that were generated as part of the insert; For those we'll need to send
                // notifications later.

                try (final PreparedStatement ps = nativeConnection.prepareStatement("""
                        INSERT INTO "POLICYVIOLATION"
                          ("UUID", "TIMESTAMP", "COMPONENT_ID", "PROJECT_ID", "POLICYCONDITION_ID", "TYPE")
                        VALUES
                          (?, ?, ?, ?, ?, ?)
                        ON CONFLICT DO NOTHING
                        RETURNING "ID"
                        """, Statement.RETURN_GENERATED_KEYS)) {
                    for (final Map.Entry<Long, PolicyViolation> entry : violationsToCreate.entries()) {
                        ps.setObject(1, UUID.randomUUID());
                        ps.setTimestamp(2, new Timestamp(entry.getValue().getTimestamp().getTime()));
                        ps.setLong(3, entry.getKey());
                        ps.setLong(4, projectId);
                        ps.setLong(5, entry.getValue().getPolicyCondition().getId());
                        ps.setString(6, entry.getValue().getType().name());
                        ps.addBatch();
                    }
                    ps.executeBatch();

                    final ResultSet rs = ps.getGeneratedKeys();
                    while (rs.next()) {
                        newViolationIds.add(rs.getLong(1));
                    }
                }
            }

            if (!violationIdsToDelete.isEmpty()) {
                final Array violationIdsToDeleteArray =
                        nativeConnection.createArrayOf("BIGINT", violationIdsToDelete.toArray(new Long[0]));

                // First, bulk-delete any analysis comments attached to the violations.
                try (final PreparedStatement ps = nativeConnection.prepareStatement("""
                        DELETE FROM
                          "VIOLATIONANALYSISCOMMENT" AS "VAC"
                        USING
                          "VIOLATIONANALYSIS" AS "VA"
                        WHERE
                          "VAC"."VIOLATIONANALYSIS_ID" = "VA"."ID"
                          AND "VA"."POLICYVIOLATION_ID" = ANY(?)
                        """)) {
                    ps.setArray(1, violationIdsToDeleteArray);
                    ps.execute();
                }

                // Then, bulk-delete any analyses attached to the violations.
                try (final PreparedStatement ps = nativeConnection.prepareStatement("""
                        DELETE FROM
                          "VIOLATIONANALYSIS"
                        WHERE
                          "POLICYVIOLATION_ID" = ANY(?)
                        """)) {
                    ps.setArray(1, violationIdsToDeleteArray);
                    ps.execute();
                }

                // Finally, bulk-delete the actual violations.
                try (final PreparedStatement ps = nativeConnection.prepareStatement("""
                        DELETE FROM
                          "POLICYVIOLATION"
                        WHERE
                          "ID" = ANY(?)
                        """)) {
                    ps.setArray(1, violationIdsToDeleteArray);
                    ps.execute();
                }
            }

            nativeConnection.commit();
        } catch (Exception e) {
            try {
                nativeConnection.rollback();
            } catch (SQLException ex) {
                throw new RuntimeException(ex);
            }

            throw new RuntimeException(e);
        } finally {
            try {
                if (originalAutoCommit != null) {
                    nativeConnection.setAutoCommit(originalAutoCommit);
                }
                if (originalTrxIsolation != null) {
                    nativeConnection.setTransactionIsolation(originalTrxIsolation);
                }
            } catch (SQLException e) {
                LOGGER.error("Failed to restore original connection settings (autoCommit=%s, trxIsolation=%d)"
                        .formatted(originalAutoCommit, originalTrxIsolation), e);
            }

            jdoConnection.close();
        }

        return newViolationIds;
    }

    List<Policy> getApplicablePolicies(final Project project) {
        var filter = """
                (this.projects.isEmpty() && this.tags.isEmpty())
                    || (this.projects.contains(:project)
                """;
        var params = new HashMap<String, Object>();
        params.put("project", project);

        // To compensate for missing support for recursion of Common Table Expressions (CTEs)
        // in JDO, we have to fetch the UUIDs of all parent projects upfront. Otherwise, we'll
        // not be able to evaluate whether the policy is inherited from parent projects.
        var variables = "";
        final List<UUID> parentUuids = getParents(project);
        if (!parentUuids.isEmpty()) {
            filter += """
                    || (this.includeChildren
                        && this.projects.contains(parentVar)
                        && :parentUuids.contains(parentVar.uuid))
                    """;
            variables += "org.dependencytrack.model.Project parentVar";
            params.put("parentUuids", parentUuids);
        }
        filter += ")";

        // DataNucleus generates an invalid SQL query when using the idiomatic solution.
        // The following works, but it's ugly and likely doesn't perform well if the project
        // has many tags. Worth trying the idiomatic way again once DN has been updated to > 6.0.4.
        //
        // filter += " || (this.tags.contains(commonTag) && :project.tags.contains(commonTag))";
        // variables += "org.dependencytrack.model.Tag commonTag";
        if (project.getTags() != null && !project.getTags().isEmpty()) {
            filter += " || (";
            for (int i = 0; i < project.getTags().size(); i++) {
                filter += "this.tags.contains(:tag" + i + ")";
                params.put("tag" + i, project.getTags().get(i));
                if (i < (project.getTags().size() - 1)) {
                    filter += " || ";
                }
            }
            filter += ")";
        }

        final List<Policy> policies;
        final Query<Policy> query = pm.newQuery(Policy.class);
        try {
            query.setFilter(filter);
            query.setNamedParameters(params);
            if (!variables.isEmpty()) {
                query.declareVariables(variables);
            }
            policies = List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }

        return policies;
    }

    List<UUID> getParents(final Project project) {
        return getParents(project.getUuid(), new ArrayList<>());
    }

    List<UUID> getParents(final UUID uuid, final List<UUID> parents) {
        final UUID parentUuid;
        final Query<Project> query = pm.newQuery(Project.class);
        try {
            query.setFilter("uuid == :uuid && parent != null");
            query.setParameters(uuid);
            query.setResult("parent.uuid");
            parentUuid = query.executeResultUnique(UUID.class);
        } finally {
            query.closeAll();
        }

        if (parentUuid == null) {
            return parents;
        }

        parents.add(parentUuid);
        return getParents(parentUuid, parents);
    }

    boolean isDirectDependency(final org.dependencytrack.proto.policy.v1.Component component) {
        String queryString = /* language=SQL */ """
                SELECT COUNT(*)
                  FROM "COMPONENT" "C"
                 INNER JOIN "PROJECT" "P"
                    ON "P"."ID" = "C"."PROJECT_ID"
                   AND "P"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :uuid))
                 WHERE "C"."UUID" = :uuid
                """;
        final Query<?> query = pm.newQuery(Query.SQL, queryString);
        query.setNamedParameters(Map.of("uuid", UUID.fromString(component.getUuid())));
        long result;
        try {
            result = query.executeResultUnique(Long.class);
        } finally {
            query.closeAll();
        }
        return result == 1;
    }

    @Override
    public void close() {
        // Noop
    }

}
