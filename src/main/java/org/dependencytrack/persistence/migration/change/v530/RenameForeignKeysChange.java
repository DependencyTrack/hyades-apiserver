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
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class RenameForeignKeysChange implements CustomTaskChange {

    private record ForeignKeyDefinition(String targetTable, String referencedTable) {
    }

    record ForeignKeyNameMapping(String table, String oldName, String newName) {
    }

    private static ForeignKeyDefinition foreignKeyDef(final String targetTable, final String referencedTale) {
        return new ForeignKeyDefinition(targetTable, referencedTale);
    }

    private static final Map<ForeignKeyDefinition, String> FOREIGN_KEYS_NAMES = Map.ofEntries(
            Map.entry(
                    foreignKeyDef("AFFECTEDVERSIONATTRIBUTION", "VULNERABLESOFTWARE"),
                    "AFFECTEDVERSIONATTRIBUTION_VULNERABLESOFTWARE_FK"
            ),
            Map.entry(
                    foreignKeyDef("ANALYSISCOMMENT", "ANALYSIS"),
                    "ANALYSISCOMMENT_ANALYSIS_FK"
            ),
            Map.entry(
                    foreignKeyDef("ANALYSIS", "COMPONENT"),
                    "ANALYSIS_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("ANALYSIS", "PROJECT"),
                    "ANALYSIS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("ANALYSIS", "VULNERABILITY"),
                    "ANALYSIS_VULNERABILITY_FK"
            ),
            Map.entry(
                    foreignKeyDef("APIKEYS_TEAMS", "TEAM"),
                    "APIKEYS_TEAMS_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("APIKEYS_TEAMS", "APIKEY"),
                    "APIKEYS_TEAMS_APIKEY_FK"
            ),
            Map.entry(
                    foreignKeyDef("BOM", "PROJECT"),
                    "BOM_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("COMPONENTS_VULNERABILITIES", "COMPONENT"),
                    "COMPONENTS_VULNERABILITIES_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("COMPONENTS_VULNERABILITIES", "VULNERABILITY"),
                    "COMPONENTS_VULNERABILITIES_VULNERABILITY_FK"
            ),
            Map.entry(
                    foreignKeyDef("COMPONENT", "COMPONENT"),
                    "COMPONENT_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("COMPONENT", "PROJECT"),
                    "COMPONENT_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("COMPONENT", "LICENSE"),
                    "COMPONENT_LICENSE_FK"
            ),
            Map.entry(
                    foreignKeyDef("DEPENDENCYMETRICS", "COMPONENT"),
                    "DEPENDENCYMETRICS_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("DEPENDENCYMETRICS", "PROJECT"),
                    "DEPENDENCYMETRICS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("FINDINGATTRIBUTION", "COMPONENT"),
                    "FINDINGATTRIBUTION_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("FINDINGATTRIBUTION", "PROJECT"),
                    "FINDINGATTRIBUTION_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("FINDINGATTRIBUTION", "VULNERABILITY"),
                    "FINDINGATTRIBUTION_VULNERABILITY_FK"
            ),
            Map.entry(
                    foreignKeyDef("INTEGRITY_ANALYSIS", "COMPONENT"),
                    "INTEGRITY_ANALYSIS_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("LDAPUSERS_PERMISSIONS", "LDAPUSER"),
                    "LDAPUSERS_PERMISSIONS_LDAPUSER_FK"
            ),
            Map.entry(
                    foreignKeyDef("LDAPUSERS_PERMISSIONS", "PERMISSION"),
                    "LDAPUSERS_PERMISSIONS_PERMISSION_FK"
            ),
            Map.entry(
                    foreignKeyDef("LDAPUSERS_TEAMS", "TEAM"),
                    "LDAPUSERS_TEAMS_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("LDAPUSERS_TEAMS", "LDAPUSER"),
                    "LDAPUSERS_TEAMS_LDAPUSER_FK"
            ),
            Map.entry(
                    foreignKeyDef("LICENSEGROUP_LICENSE", "LICENSEGROUP"),
                    "LICENSEGROUP_LICENSE_LICENSEGROUP_FK"
            ),
            Map.entry(
                    foreignKeyDef("LICENSEGROUP_LICENSE", "LICENSE"),
                    "LICENSEGROUP_LICENSE_LICENSE_FK"
            ),
            Map.entry(
                    foreignKeyDef("MANAGEDUSERS_PERMISSIONS", "MANAGEDUSER"),
                    "MANAGEDUSERS_PERMISSIONS_MANAGEDUSER_FK"
            ),
            Map.entry(
                    foreignKeyDef("MANAGEDUSERS_PERMISSIONS", "PERMISSION"),
                    "MANAGEDUSERS_PERMISSIONS_PERMISSION_FK"
            ),
            Map.entry(
                    foreignKeyDef("MANAGEDUSERS_TEAMS", "TEAM"),
                    "MANAGEDUSERS_TEAMS_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("MANAGEDUSERS_TEAMS", "MANAGEDUSER"),
                    "MANAGEDUSERS_TEAMS_MANAGEDUSER_FK"
            ),
            Map.entry(
                    foreignKeyDef("MAPPEDLDAPGROUP", "TEAM"),
                    "MAPPEDLDAPGROUP_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("MAPPEDOIDCGROUP", "OIDCGROUP"),
                    "MAPPEDOIDCGROUP_OIDCGROUP_FK"
            ),
            Map.entry(
                    foreignKeyDef("MAPPEDOIDCGROUP", "TEAM"),
                    "MAPPEDOIDCGROUP_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("NOTIFICATIONRULE", "NOTIFICATIONPUBLISHER"),
                    "NOTIFICATIONRULE_NOTIFICATIONPUBLISHER_FK"
            ),
            Map.entry(
                    foreignKeyDef("NOTIFICATIONRULE_PROJECTS", "NOTIFICATIONRULE"),
                    "NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_FK"
            ),
            Map.entry(
                    foreignKeyDef("NOTIFICATIONRULE_PROJECTS", "PROJECT"),
                    "NOTIFICATIONRULE_PROJECTS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("NOTIFICATIONRULE_TEAMS", "NOTIFICATIONRULE"),
                    "NOTIFICATIONRULE_TEAMS_NOTIFICATIONRULE_FK"
            ),
            Map.entry(
                    foreignKeyDef("NOTIFICATIONRULE_TEAMS", "TEAM"),
                    "NOTIFICATIONRULE_TEAMS_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("OIDCUSERS_PERMISSIONS", "PERMISSION"),
                    "OIDCUSERS_PERMISSIONS_PERMISSION_FK"
            ),
            Map.entry(
                    foreignKeyDef("OIDCUSERS_PERMISSIONS", "OIDCUSER"),
                    "OIDCUSERS_PERMISSIONS_OIDCUSER_FK"
            ),
            Map.entry(
                    foreignKeyDef("OIDCUSERS_TEAMS", "OIDCUSER"),
                    "OIDCUSERS_TEAMS_OIDCUSER_FK"
            ),
            Map.entry(
                    foreignKeyDef("OIDCUSERS_TEAMS", "TEAM"),
                    "OIDCUSERS_TEAMS_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICYCONDITION", "POLICY"),
                    "POLICYCONDITION_POLICY_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICYVIOLATION", "COMPONENT"),
                    "POLICYVIOLATION_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICYVIOLATION", "PROJECT"),
                    "POLICYVIOLATION_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICYVIOLATION", "POLICYCONDITION"),
                    "POLICYVIOLATION_POLICYCONDITION_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICY_PROJECTS", "POLICY"),
                    "POLICY_PROJECTS_POLICY_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICY_PROJECTS", "PROJECT"),
                    "POLICY_PROJECTS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICY_TAGS", "POLICY"),
                    "POLICY_TAGS_POLICY_FK"
            ),
            Map.entry(
                    foreignKeyDef("POLICY_TAGS", "TAG"),
                    "POLICY_TAGS_TAG_FK"
            ),
            Map.entry(
                    foreignKeyDef("PROJECTMETRICS", "PROJECT"),
                    "PROJECTMETRICS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("PROJECTS_TAGS", "TAG"),
                    "PROJECTS_TAGS_TAG_FK"
            ),
            Map.entry(
                    foreignKeyDef("PROJECTS_TAGS", "PROJECT"),
                    "PROJECTS_TAGS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("PROJECT_ACCESS_TEAMS", "PROJECT"),
                    "PROJECT_ACCESS_TEAMS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("PROJECT_ACCESS_TEAMS", "TEAM"),
                    "PROJECT_ACCESS_TEAMS_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("PROJECT", "PROJECT"),
                    "PROJECT_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("PROJECT_PROPERTY", "PROJECT"),
                    "PROJECT_PROPERTY_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("SERVICECOMPONENTS_VULNERABILITIES", "VULNERABILITY"),
                    "SERVICECOMPONENTS_VULNERABILITIES_VULNERABILITY_FK"
            ),
            Map.entry(
                    foreignKeyDef("SERVICECOMPONENTS_VULNERABILITIES", "SERVICECOMPONENT"),
                    "SERVICECOMPONENTS_VULNERABILITIES_SERVICECOMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("SERVICECOMPONENT", "SERVICECOMPONENT"),
                    "SERVICECOMPONENT_SERVICECOMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("SERVICECOMPONENT", "PROJECT"),
                    "SERVICECOMPONENT_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("TEAMS_PERMISSIONS", "TEAM"),
                    "TEAMS_PERMISSIONS_TEAM_FK"
            ),
            Map.entry(
                    foreignKeyDef("TEAMS_PERMISSIONS", "PERMISSION"),
                    "TEAMS_PERMISSIONS_PERMISSION_FK"
            ),
            Map.entry(
                    foreignKeyDef("VEX", "PROJECT"),
                    "VEX_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("VIOLATIONANALYSISCOMMENT", "VIOLATIONANALYSIS"),
                    "VIOLATIONANALYSISCOMMENT_VIOLATIONANALYSIS_FK"
            ),
            Map.entry(
                    foreignKeyDef("VIOLATIONANALYSIS", "COMPONENT"),
                    "VIOLATIONANALYSIS_COMPONENT_FK"
            ),
            Map.entry(
                    foreignKeyDef("VIOLATIONANALYSIS", "POLICYVIOLATION"),
                    "VIOLATIONANALYSIS_POLICYVIOLATION_FK"
            ),
            Map.entry(
                    foreignKeyDef("VIOLATIONANALYSIS", "PROJECT"),
                    "VIOLATIONANALYSIS_PROJECT_FK"
            ),
            Map.entry(
                    foreignKeyDef("VULNERABLESOFTWARE_VULNERABILITIES", "VULNERABILITY"),
                    "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABILITY_FK"
            ),
            Map.entry(
                    foreignKeyDef("VULNERABLESOFTWARE_VULNERABILITIES", "VULNERABLESOFTWARE"),
                    "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABLESOFTWARE_FK"
            ),
            Map.entry(
                    foreignKeyDef("WORKFLOW_STATE", "WORKFLOW_STATE"),
                    "WORKFLOW_STATE_WORKFLOW_STATE_FK"
            ),
            Map.entry(
                    foreignKeyDef("AFFECTEDVERSIONATTRIBUTION", "VULNERABILITY"),
                    "AFFECTEDVERSIONATTRIBUTION_VULNERABILITY_FK"
            )
    );

    private final List<ForeignKeyNameMapping> renamedForeignKeys = new ArrayList<>();

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
            final List<ForeignKeyNameMapping> foreignKeyNameMappings = getForeignNameMappings(connection);
            renamedForeignKeys.addAll(renameForeignKeys(connection, foreignKeyNameMappings));
        } catch (DatabaseException | SQLException e) {
            throw new CustomChangeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getConfirmationMessage() {
        if (renamedForeignKeys.isEmpty()) {
            return "No foreign keys renamed";
        }

        return "Renamed foreign keys:\n" + renamedForeignKeys.stream()
                .sorted(Comparator.comparing(ForeignKeyNameMapping::oldName))
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

    static List<ForeignKeyNameMapping> getForeignNameMappings(final JdbcConnection connection) throws DatabaseException, SQLException {
        return switch (connection.getDatabaseProductName()) {
            case "PostgreSQL" -> getForeignKeyNameMappingsFromPostgres(connection);
            default -> throw new IllegalStateException();
        };
    }

    private static List<ForeignKeyNameMapping> getForeignKeyNameMappingsFromPostgres(final JdbcConnection connection) throws DatabaseException, SQLException {
        final var foreignKeyNameMappings = new ArrayList<ForeignKeyNameMapping>();

        try (final var stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery("""
                    SELECT
                        tc.constraint_name AS foreign_key_name,
                        tc.table_name AS target_table_name,
                        kcu.column_name,
                        ccu.table_name AS foreign_table_name,
                        ccu.column_name AS foreign_column_name
                    FROM information_schema.table_constraints AS tc
                    JOIN information_schema.key_column_usage AS kcu
                        ON tc.constraint_name = kcu.constraint_name
                        AND tc.table_schema = kcu.table_schema
                    JOIN information_schema.constraint_column_usage AS ccu
                        ON ccu.constraint_name = tc.constraint_name
                    WHERE tc.constraint_type = 'FOREIGN KEY'
                        AND tc.constraint_name ~ '_FK[0-9]+$'
                    """);
            while (rs.next()) {
                final String tableName = rs.getString("target_table_name");
                final String referencedTableName = rs.getString("foreign_table_name");
                final String oldForeignKeyName = rs.getString("foreign_key_name");
                final String newForeignKeyName = FOREIGN_KEYS_NAMES.get(foreignKeyDef(tableName, referencedTableName));
                foreignKeyNameMappings.add(new ForeignKeyNameMapping(tableName, oldForeignKeyName, newForeignKeyName));
            }
        }
        return foreignKeyNameMappings;
    }

    private static List<ForeignKeyNameMapping> renameForeignKeys(final JdbcConnection connection, final List<ForeignKeyNameMapping> foreignKeyNameMappings) throws DatabaseException, SQLException {
        return switch (connection.getDatabaseProductName()) {
            case "PostgreSQL" -> renameForeignKeysForPostgres(connection, foreignKeyNameMappings);
            default -> throw new IllegalStateException();
        };
    }


    @SuppressWarnings("SqlSourceToSinkFlow")
    private static List<ForeignKeyNameMapping> renameForeignKeysForPostgres(final JdbcConnection connection, final List<ForeignKeyNameMapping> foreignKeyNameMappings) throws DatabaseException, SQLException {
        final var renamedForeignKeys = new ArrayList<ForeignKeyNameMapping>();

        try (final Statement stmt = connection.createStatement()) {
            for (final ForeignKeyNameMapping nameMapping : foreignKeyNameMappings) {
                if (nameMapping.newName() == null || nameMapping.newName().equals(nameMapping.oldName())) {
                    continue;
                }

                stmt.addBatch("""
                        ALTER TABLE "%s" RENAME CONSTRAINT "%s" TO "%s"
                        """.formatted(nameMapping.table(), nameMapping.oldName(), nameMapping.newName()));
                renamedForeignKeys.add(nameMapping);
            }
            stmt.executeBatch();
        }
        return renamedForeignKeys;
    }
}
