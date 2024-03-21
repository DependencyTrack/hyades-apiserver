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
package org.dependencytrack.persistence.migration.change.v530;

import liquibase.change.custom.CustomTaskChange;
import liquibase.database.Database;
import liquibase.database.jvm.JdbcConnection;
import liquibase.exception.CustomChangeException;
import liquibase.exception.DatabaseException;
import liquibase.exception.SetupException;
import liquibase.exception.ValidationErrors;
import liquibase.resource.ResourceAccessor;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class RenameNumberedIndexesChange implements CustomTaskChange {

    private record IndexDefinition(String table, Set<String> columns) {
    }

    record IndexNameMapping(String oldName, String newName) {
    }

    private static IndexDefinition indexDef(final String table, final String... columns) {
        return new IndexDefinition(table, Set.copyOf(Arrays.asList(columns)));
    }

    private static final Map<IndexDefinition, String> INDEX_NAMES = Map.ofEntries(
            Map.entry(
                    indexDef("AFFECTEDVERSIONATTRIBUTION", "VULNERABILITY"),
                    "AFFECTEDVERSIONATTRIBUTION_VULNERABILITY_IDX"
            ),
            Map.entry(
                    indexDef("AFFECTEDVERSIONATTRIBUTION", "VULNERABLE_SOFTWARE"),
                    "AFFECTEDVERSIONATTRIBUTION_VULNERABLE_SOFTWARE_IDX"
            ),
            Map.entry(
                    indexDef("ANALYSIS", "PROJECT_ID"),
                    "ANALYSIS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("ANALYSIS", "VULNERABILITY_ID"),
                    "ANALYSIS_VULNERABILITY_ID_IDX"
            ),
            Map.entry(
                    indexDef("ANALYSIS", "COMPONENT_ID"),
                    "ANALYSIS_COMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("ANALYSISCOMMENT", "ANALYSIS_ID"),
                    "ANALYSISCOMMENT_ANALYSIS_ID_IDX"
            ),
            Map.entry(
                    indexDef("APIKEYS_TEAMS", "TEAM_ID"),
                    "APIKEYS_TEAMS_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("APIKEYS_TEAMS", "APIKEY_ID"),
                    "APIKEYS_TEAMS_APIKEY_ID_IDX"
            ),
            Map.entry(
                    indexDef("BOM", "PROJECT_ID"),
                    "BOM_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("COMPONENT", "LICENSE_ID"),
                    "COMPONENT_LICENSE_ID_IDX"
            ),
            Map.entry(
                    indexDef("COMPONENT", "PARENT_COMPONENT_ID"),
                    "COMPONENT_PARENT_COMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("COMPONENTS_VULNERABILITIES", "COMPONENT_ID"),
                    "COMPONENTS_VULNERABILITIES_COMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("COMPONENTS_VULNERABILITIES", "VULNERABILITY_ID"),
                    "COMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX"
            ),
            Map.entry(
                    indexDef("DEPENDENCYMETRICS", "COMPONENT_ID"),
                    "DEPENDENCYMETRICS_COMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("DEPENDENCYMETRICS", "PROJECT_ID"),
                    "DEPENDENCYMETRICS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("FINDINGATTRIBUTION", "VULNERABILITY_ID"),
                    "FINDINGATTRIBUTION_VULNERABILITY_ID_IDX"
            ),
            Map.entry(
                    indexDef("FINDINGATTRIBUTION", "PROJECT_ID"),
                    "FINDINGATTRIBUTION_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("FINDINGATTRIBUTION", "COMPONENT_ID"),
                    "FINDINGATTRIBUTION_COMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("LDAPUSERS_PERMISSIONS", "PERMISSION_ID"),
                    "LDAPUSERS_PERMISSIONS_PERMISSION_ID_IDX"
            ),
            Map.entry(
                    indexDef("LDAPUSERS_PERMISSIONS", "LDAPUSER_ID"),
                    "LDAPUSERS_PERMISSIONS_LDAPUSER_ID_IDX"
            ),
            Map.entry(
                    indexDef("LDAPUSERS_TEAMS", "LDAPUSER_ID"),
                    "LDAPUSERS_TEAMS_LDAPUSER_ID_IDX"
            ),
            Map.entry(
                    indexDef("LDAPUSERS_TEAMS", "TEAM_ID"),
                    "LDAPUSERS_TEAMS_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("LICENSEGROUP_LICENSE", "LICENSE_ID"),
                    "LICENSEGROUP_LICENSE_LICENSE_ID_IDX"
            ),
            Map.entry(
                    indexDef("LICENSEGROUP_LICENSE", "LICENSEGROUP_ID"),
                    "LICENSEGROUP_LICENSE_LICENSEGROUP_ID_IDX"
            ),
            Map.entry(
                    indexDef("MANAGEDUSERS_PERMISSIONS", "MANAGEDUSER_ID"),
                    "MANAGEDUSERS_PERMISSIONS_MANAGEDUSER_ID_IDX"
            ),
            Map.entry(
                    indexDef("MANAGEDUSERS_PERMISSIONS", "PERMISSION_ID"),
                    "MANAGEDUSERS_PERMISSIONS_PERMISSION_ID_IDX"
            ),
            Map.entry(
                    indexDef("MANAGEDUSERS_TEAMS", "MANAGEDUSER_ID"),
                    "MANAGEDUSERS_TEAMS_MANAGEDUSER_ID_IDX"
            ),
            Map.entry(
                    indexDef("MANAGEDUSERS_TEAMS", "TEAM_ID"),
                    "MANAGEDUSERS_TEAMS_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("MAPPEDLDAPGROUP", "TEAM_ID"),
                    "MAPPEDLDAPGROUP_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("MAPPEDOIDCGROUP", "GROUP_ID"),
                    "MAPPEDOIDCGROUP_GROUP_ID_IDX"
            ),
            Map.entry(
                    indexDef("MAPPEDOIDCGROUP", "TEAM_ID"),
                    "MAPPEDOIDCGROUP_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("NOTIFICATIONRULE", "PUBLISHER"),
                    "NOTIFICATIONRULE_PUBLISHER_IDX"
            ),
            Map.entry(
                    indexDef("NOTIFICATIONRULE_PROJECTS", "PROJECT_ID"),
                    "NOTIFICATIONRULE_PROJECTS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("NOTIFICATIONRULE_PROJECTS", "NOTIFICATIONRULE_ID"),
                    "NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_ID_IDX"
            ),
            Map.entry(
                    indexDef("NOTIFICATIONRULE_TEAMS", "TEAM_ID"),
                    "NOTIFICATIONRULE_TEAMS_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("NOTIFICATIONRULE_TEAMS", "NOTIFICATIONRULE_ID"),
                    "NOTIFICATIONRULE_TEAMS_NOTIFICATIONRULE_ID_IDX"
            ),
            Map.entry(
                    indexDef("OIDCUSERS_PERMISSIONS", "OIDCUSER_ID"),
                    "OIDCUSERS_PERMISSIONS_OIDCUSER_ID_IDX"
            ),
            Map.entry(
                    indexDef("OIDCUSERS_PERMISSIONS", "PERMISSION_ID"),
                    "OIDCUSERS_PERMISSIONS_PERMISSION_ID_IDX"
            ),
            Map.entry(
                    indexDef("OIDCUSERS_TEAMS", "OIDCUSERS_ID"),
                    "OIDCUSERS_TEAMS_OIDCUSERS_ID_IDX"
            ),
            Map.entry(
                    indexDef("OIDCUSERS_TEAMS", "TEAM_ID"),
                    "OIDCUSERS_TEAMS_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("POLICYCONDITION", "POLICY_ID"),
                    "POLICYCONDITION_POLICY_ID_IDX"
            ),
            Map.entry(
                    indexDef("POLICYVIOLATION", "POLICYCONDITION_ID"),
                    "POLICYVIOLATION_POLICYCONDITION_ID_IDX"
            ),
            Map.entry(
                    indexDef("POLICY_PROJECTS", "PROJECT_ID"),
                    "POLICY_PROJECTS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("POLICY_PROJECTS", "POLICY_ID"),
                    "POLICY_PROJECTS_POLICY_ID_IDX"
            ),
            Map.entry(
                    indexDef("POLICY_TAGS", "POLICY_ID"),
                    "POLICY_TAGS_POLICY_ID_IDX"
            ),
            Map.entry(
                    indexDef("POLICY_TAGS", "TAG_ID"),
                    "POLICY_TAGS_TAG_ID_IDX"
            ),
            Map.entry(
                    indexDef("PROJECT", "PARENT_PROJECT_ID"),
                    "PROJECT_PARENT_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("PROJECTMETRICS", "PROJECT_ID"),
                    "PROJECTMETRICS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("PROJECTS_TAGS", "PROJECT_ID"),
                    "PROJECTS_TAGS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("PROJECTS_TAGS", "TAG_ID"),
                    "PROJECTS_TAGS_TAG_ID_IDX"
            ),
            Map.entry(
                    indexDef("PROJECT_ACCESS_TEAMS", "PROJECT_ID"),
                    "PROJECT_ACCESS_TEAMS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("PROJECT_ACCESS_TEAMS", "TEAM_ID"),
                    "PROJECT_ACCESS_TEAMS_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("PROJECT_PROPERTY", "PROJECT_ID"),
                    "PROJECT_PROPERTY_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("SERVICECOMPONENT", "PROJECT_ID"),
                    "SERVICECOMPONENT_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("SERVICECOMPONENT", "PARENT_SERVICECOMPONENT_ID"),
                    "SERVICECOMPONENT_PARENT_SERVICECOMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("SERVICECOMPONENTS_VULNERABILITIES", "SERVICECOMPONENT_ID"),
                    "SERVICECOMPONENTS_VULNERABILITIES_SERVICECOMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("SERVICECOMPONENTS_VULNERABILITIES", "VULNERABILITY_ID"),
                    "SERVICECOMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX"
            ),
            Map.entry(
                    indexDef("TEAMS_PERMISSIONS", "PERMISSION_ID"),
                    "TEAMS_PERMISSIONS_PERMISSION_ID_IDX"
            ),
            Map.entry(
                    indexDef("TEAMS_PERMISSIONS", "TEAM_ID"),
                    "TEAMS_PERMISSIONS_TEAM_ID_IDX"
            ),
            Map.entry(
                    indexDef("VEX", "PROJECT_ID"),
                    "VEX_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("VIOLATIONANALYSIS", "COMPONENT_ID"),
                    "VIOLATIONANALYSIS_COMPONENT_ID_IDX"
            ),
            Map.entry(
                    indexDef("VIOLATIONANALYSIS", "POLICYVIOLATION_ID"),
                    "VIOLATIONANALYSIS_POLICYVIOLATION_ID_IDX"
            ),
            Map.entry(
                    indexDef("VIOLATIONANALYSIS", "PROJECT_ID"),
                    "VIOLATIONANALYSIS_PROJECT_ID_IDX"
            ),
            Map.entry(
                    indexDef("VIOLATIONANALYSISCOMMENT", "VIOLATIONANALYSIS_ID"),
                    "VIOLATIONANALYSISCOMMENT_VIOLATIONANALYSIS_ID_IDX"
            ),
            Map.entry(
                    indexDef("VULNERABLESOFTWARE_VULNERABILITIES", "VULNERABILITY_ID"),
                    "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABILITY_ID_IDX"
            ),
            Map.entry(
                    indexDef("VULNERABLESOFTWARE_VULNERABILITIES", "VULNERABLESOFTWARE_ID"),
                    "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABLESOFTWARE_ID_IDX"
            ),
            Map.entry(
                    indexDef("WORKFLOW_STATE", "PARENT_STEP_ID"),
                    "WORKFLOW_STATE_PARENT_STEP_ID_IDX"
            ),
            Map.entry(
                    indexDef("INTEGRITY_ANALYSIS", "COMPONENT_ID"),
                    "INTEGRITY_ANALYSIS_COMPONENT_ID_IDX"
            )
    );

    private final List<IndexNameMapping> renamedIndexes = new ArrayList<>();

    /**
     * {@inheritDoc}
     */
    @Override
    public void setUp() throws SetupException {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void execute(final Database database) throws CustomChangeException {
        final var connection = (JdbcConnection) database.getConnection();
        if (!"PostgreSQL".equals(database.getDatabaseProductName())) {
            throw new CustomChangeException("Database %s is not supported".formatted(database.getDatabaseProductName()));
        }

        try {
            final List<IndexNameMapping> indexNameMappings = getIndexNameMappings(connection);
            renamedIndexes.addAll(renameIndexes(connection, indexNameMappings));
        } catch (DatabaseException | SQLException e) {
            throw new CustomChangeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getConfirmationMessage() {
        if (renamedIndexes.isEmpty()) {
            return "No indexes renamed";
        }

        return "Renamed indexes:\n" + renamedIndexes.stream()
                .sorted(Comparator.comparing(IndexNameMapping::oldName))
                .map(mapping -> " - %s -> %s".formatted(mapping.oldName(), mapping.newName()))
                .collect(Collectors.joining("\n"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setFileOpener(final ResourceAccessor resourceAccessor) {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ValidationErrors validate(final Database database) {
        return null;
    }

    private static List<IndexNameMapping> getIndexNameMappings(final JdbcConnection connection) throws DatabaseException, SQLException {
        return switch (connection.getDatabaseProductName()) {
            case "PostgreSQL" -> getIndexNameMappingsFromPostgres(connection);
            default -> throw new IllegalStateException();
        };
    }

    static List<IndexNameMapping> getIndexNameMappingsFromPostgres(final JdbcConnection connection) throws DatabaseException, SQLException {
        final var indexNameMapping = new ArrayList<IndexNameMapping>();

        try (final var stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery("""
                    SELECT
                      t.relname AS table_name,
                      i.relname AS index_name,
                      ARRAY_TO_STRING(ARRAY_AGG(a.attname), ',') AS column_names
                    FROM
                      pg_class t,
                      pg_class i,
                      pg_index ix,
                      pg_attribute a
                    where
                      t.oid = ix.indrelid
                       and i.oid = ix.indexrelid
                       and a.attrelid = t.oid
                       and a.attnum = ANY(ix.indkey)
                       and t.relkind = 'r'
                       and t.relname not like 'pg%'
                       and i.relname ~ '_N[0-9]+$'
                     group by
                         t.relname,
                         i.relname
                     order by
                         t.relname,
                         i.relname;
                    """);
            while (rs.next()) {
                final String tableName = rs.getString("table_name");
                final String oldIndexName = rs.getString("index_name");
                final String[] columnNames = rs.getString("column_names").split(",");
                final String newIndexName = INDEX_NAMES.get(indexDef(tableName, columnNames));
                indexNameMapping.add(new IndexNameMapping(oldIndexName, newIndexName));
            }
        }

        return indexNameMapping;
    }

    private static List<IndexNameMapping> renameIndexes(final JdbcConnection connection, final List<IndexNameMapping> indexNameMappings) throws DatabaseException, SQLException {
        return switch (connection.getDatabaseProductName()) {
            case "PostgreSQL" -> renameIndexesForPostgres(connection, indexNameMappings);
            default -> throw new IllegalStateException();
        };
    }


    private static List<IndexNameMapping> renameIndexesForPostgres(final JdbcConnection connection, final List<IndexNameMapping> indexNameMappings) throws DatabaseException, SQLException {
        final var renamedIndexes = new ArrayList<IndexNameMapping>();

        try (final Statement stmt = connection.createStatement()) {
            for (final IndexNameMapping nameMapping : indexNameMappings) {
                if (nameMapping.newName() == null) {
                    continue;
                }

                stmt.addBatch("""
                        ALTER INDEX "%s" RENAME TO "%s"
                        """.formatted(nameMapping.oldName(), nameMapping.newName));
                renamedIndexes.add(nameMapping);
            }
            stmt.executeBatch();
        }
        return renamedIndexes;
    }
}
