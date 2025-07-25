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
package org.dependencytrack.persistence;

import alpine.server.auth.PasswordService;
import org.apache.commons.lang3.SerializationUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.DefaultRepository;
import org.dependencytrack.model.License;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Update;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_DEFAULT_OBJECTS_VERSION;
import static org.dependencytrack.model.ConfigPropertyConstants.NOTIFICATION_TEMPLATE_BASE_DIR;
import static org.dependencytrack.model.ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED;

/**
 * @since 5.6.0
 */
public final class DatabaseSeedingInitTask implements InitTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseSeedingInitTask.class);

    private static final Map<String, List<String>> DEFAULT_TEAM_PERMISSIONS = Map.of(
            "Administrators", Stream.of(Permissions.values()).map(Permissions::name).toList(),
            "Portfolio Managers", List.of(Permissions.Constants.PORTFOLIO_MANAGEMENT),
            "Automation", List.of(Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.BOM_CREATE),
            "Badge Viewers", List.of(Permissions.Constants.BADGES_READ));

    private static final Map<String, List<String>> DEFAULT_ROLE_PERMISSIONS = Map.of(
            "Project Admin", List.of(
                    Permissions.Constants.BADGES_READ,
                    Permissions.Constants.BOM_READ,
                    Permissions.Constants.BOM_CREATE,
                    Permissions.Constants.FINDING_CREATE,
                    Permissions.Constants.FINDING_READ,
                    Permissions.Constants.FINDING_UPDATE,
                    Permissions.Constants.POLICY_VIOLATION_CREATE,
                    Permissions.Constants.POLICY_VIOLATION_READ,
                    Permissions.Constants.POLICY_VIOLATION_UPDATE,
                    Permissions.Constants.PROJECT_READ,
                    Permissions.Constants.PROJECT_UPDATE,
                    Permissions.Constants.PROJECT_DELETE),
            "Project Auditor", List.of(
                    Permissions.Constants.BADGES_READ,
                    Permissions.Constants.BOM_READ,
                    Permissions.Constants.FINDING_READ,
                    Permissions.Constants.POLICY_VIOLATION_READ,
                    Permissions.Constants.PROJECT_READ),
            "Project Editor", List.of(
                    Permissions.Constants.BOM_CREATE,
                    Permissions.Constants.BOM_READ,
                    Permissions.Constants.FINDING_READ,
                    Permissions.Constants.FINDING_UPDATE,
                    Permissions.Constants.POLICY_VIOLATION_CREATE,
                    Permissions.Constants.POLICY_VIOLATION_READ,
                    Permissions.Constants.POLICY_VIOLATION_UPDATE,
                    Permissions.Constants.PROJECT_READ,
                    Permissions.Constants.PROJECT_UPDATE),
            "Project Viewer", List.of(
                    Permissions.Constants.BADGES_READ,
                    Permissions.Constants.BOM_READ,
                    Permissions.Constants.PROJECT_READ));

    @Override
    public int priority() {
        return PRIORITY_HIGHEST - 10;
    }

    @Override
    public String name() {
        return "database.seeding";
    }

    @Override
    public void execute(final InitTaskContext ctx) throws Exception {
        final var jdbi = JdbiFactory.createLocalJdbi(ctx.dataSource());

        jdbi.useTransaction(handle -> {
            final var configPropertyDao = handle.attach(ConfigPropertyDao.class);

            final String defaultObjectsVersion = configPropertyDao
                    .getOptionalValue(INTERNAL_DEFAULT_OBJECTS_VERSION)
                    .orElse(null);
            if (ctx.config().getApplicationBuildUuid().equals(defaultObjectsVersion)) {
                LOGGER.info(
                        "Default objects already populated for build {} (timestamp: {}); Skipping",
                        ctx.config().getApplicationBuildUuid(),
                        ctx.config().getApplicationBuildTimestamp());
                return;
            }

            seedDefaultConfigProperties(handle);
            seedDefaultPermissions(handle);
            seedDefaultLicenses(handle);
            seedDefaultNotificationPublishers(handle);
            seedDefaultRepositories(handle);

            final boolean isFirstExecution = defaultObjectsVersion == null;
            if (isFirstExecution) {
                seedDefaultTeams(handle);
                seedDefaultRoles(handle);
                seedDefaultUsers(handle);
                seedDefaultLicenseGroups(handle);
            }

            configPropertyDao.setValue(
                    INTERNAL_DEFAULT_OBJECTS_VERSION,
                    ctx.config().getApplicationBuildUuid());
        });
    }

    public static void seedDefaultConfigProperties(final Handle jdbiHandle) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "CONFIGPROPERTY" ("GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE", "DESCRIPTION")
                VALUES (:groupName, :propertyName, :propertyType, :defaultPropertyValue, :description)
                ON CONFLICT ("GROUPNAME", "PROPERTYNAME") DO NOTHING
                """);

        for (final ConfigPropertyConstants configProperty : ConfigPropertyConstants.values()) {
            preparedBatch.bindBean(configProperty);
            preparedBatch.add();
        }

        final int configPropertiesCreated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created {} config properties", configPropertiesCreated);
    }

    public static void seedDefaultPermissions(final Handle jdbiHandle) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "PERMISSION" ("NAME", "DESCRIPTION")
                VALUES (:name, :description)
                ON CONFLICT ("NAME") DO NOTHING
                """);

        for (final Permissions permission : Permissions.values()) {
            preparedBatch.bind("name", permission.name());
            preparedBatch.bind("description", permission.getDescription());
            preparedBatch.add();
        }

        final int permissionsCreated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created {} permissions", permissionsCreated);
    }

    public static void seedDefaultTeams(final Handle jdbiHandle) {
        final Update update = jdbiHandle.createUpdate("""
                WITH cte_team_permission AS (
                  SELECT *
                    FROM UNNEST(:teamNames, :permissionNames) AS t(team_name, permission_name)
                ),
                cte_created_team AS (
                  INSERT INTO "TEAM" ("NAME", "UUID")
                  SELECT DISTINCT ON (team_name)
                         team_name
                       , GEN_RANDOM_UUID()
                    FROM cte_team_permission
                  RETURNING "ID" AS id
                          , "NAME" AS name
                )
                INSERT INTO "TEAMS_PERMISSIONS" ("TEAM_ID", "PERMISSION_ID")
                SELECT cte_created_team.id
                     , (SELECT "ID" FROM "PERMISSION" WHERE "NAME" = cte_team_permission.permission_name)
                  FROM cte_team_permission
                 INNER JOIN cte_created_team
                    ON cte_created_team.name = cte_team_permission.team_name
                """);

        final var teamNames = new ArrayList<String>();
        final var permissionNames = new ArrayList<String>();

        for (final Map.Entry<String, List<String>> entry : DEFAULT_TEAM_PERMISSIONS.entrySet()) {
            for (final String permissionName : entry.getValue()) {
                teamNames.add(entry.getKey());
                permissionNames.add(permissionName);
            }
        }

        update
                .bindArray("teamNames", String.class, teamNames)
                .bindArray("permissionNames", String.class, permissionNames)
                .execute();
    }

    public static void seedDefaultRoles(final Handle jdbiHandle) {
        final Update update = jdbiHandle.createUpdate("""
                WITH cte_role_permission AS (
                  SELECT *
                    FROM UNNEST(:roleNames, :permissionNames) AS t(role_name, permission_name)
                ),
                cte_created_role AS (
                  INSERT INTO "ROLE" ("NAME", "UUID")
                  SELECT DISTINCT ON (role_name)
                         role_name
                       , GEN_RANDOM_UUID()
                    FROM cte_role_permission
                  RETURNING "ID" AS id
                          , "NAME" AS name
                )
                INSERT INTO "ROLES_PERMISSIONS" ("ROLE_ID", "PERMISSION_ID")
                SELECT cte_created_role.id
                     , (SELECT "ID" FROM "PERMISSION" WHERE "NAME" = cte_role_permission.permission_name)
                  FROM cte_role_permission
                 INNER JOIN cte_created_role
                    ON cte_created_role.name = cte_role_permission.role_name
                """);

        final var roleNames = new ArrayList<String>();
        final var permissionNames = new ArrayList<String>();

        for (final Map.Entry<String, List<String>> entry : DEFAULT_ROLE_PERMISSIONS.entrySet()) {
            for (final String permissionName : entry.getValue()) {
                roleNames.add(entry.getKey());
                permissionNames.add(permissionName);
            }
        }

        update
                .bindArray("roleNames", String.class, roleNames)
                .bindArray("permissionNames", String.class, permissionNames)
                .execute();
    }

    public static void seedDefaultUsers(final Handle jdbiHandle) {
        final long adminUserId = jdbiHandle.createUpdate("""
                        INSERT INTO "USER" (
                          "TYPE", "USERNAME", "EMAIL", "PASSWORD", "LAST_PASSWORD_CHANGE"
                        , "FORCE_PASSWORD_CHANGE", "NON_EXPIRY_PASSWORD", "SUSPENDED")
                        VALUES ('MANAGED', 'admin', 'admin@localhost', :password, NOW(), TRUE, TRUE, FALSE)
                        RETURNING "ID"
                        """)
                .bind("password", new String(PasswordService.createHash("admin".toCharArray())))
                .executeAndReturnGeneratedKeys()
                .mapTo(Long.class)
                .one();

        jdbiHandle.createUpdate("""
                        INSERT INTO "USERS_TEAMS" ("USER_ID", "TEAM_ID")
                        SELECT :adminUserId, (SELECT "ID" FROM "TEAM" WHERE "NAME" = 'Administrators')
                        """)
                .bind("adminUserId", adminUserId)
                .execute();

        jdbiHandle.createUpdate("""
                        INSERT INTO "USERS_PERMISSIONS" ("USER_ID", "PERMISSION_ID")
                        SELECT :adminUserId, "PERMISSION"."ID" FROM "PERMISSION"
                        """)
                .bind("adminUserId", adminUserId)
                .execute();
    }

    public static void seedDefaultLicenses(final Handle jdbiHandle) {
        final List<License> licenses;
        try {
            licenses = new SpdxLicenseDetailParser().getLicenseDefinitions();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load license details", e);
        }

        // We have hundreds of licenses, the majority of which is *very* unlikely to change between executions
        // of this init task. In the future, we should store the version of the SPDX license list,
        // and then only sync licenses when that version has changed.
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "LICENSE" (
                  "LICENSEID", "NAME", "HEADER", "TEXT", "TEMPLATE", "ISDEPRECATED"
                , "FSFLIBRE", "ISOSIAPPROVED", "COMMENT", "SEEALSO", "UUID"
                )
                VALUES (
                  :licenseId, :name, :header, :text, :template, :deprecatedLicenseId
                , :fsfLibre, :osiApproved, :comment, :seeAlsoSerialized, GEN_RANDOM_UUID()
                )
                ON CONFLICT ("LICENSEID") DO UPDATE
                SET "NAME" = EXCLUDED."NAME"
                  , "HEADER" = EXCLUDED."HEADER"
                  , "TEXT" = EXCLUDED."TEXT"
                  , "TEMPLATE" = EXCLUDED."TEMPLATE"
                  , "ISDEPRECATED" = EXCLUDED."ISDEPRECATED"
                  , "FSFLIBRE" = EXCLUDED."FSFLIBRE"
                  , "ISOSIAPPROVED" = EXCLUDED."ISOSIAPPROVED"
                  , "COMMENT" = EXCLUDED."COMMENT"
                  , "SEEALSO" = EXCLUDED."SEEALSO"
                -- Only update when at least one relevant field has changed.
                WHERE "LICENSE"."NAME" IS DISTINCT FROM EXCLUDED."NAME"
                   OR "LICENSE"."HEADER" IS DISTINCT FROM EXCLUDED."HEADER"
                   OR "LICENSE"."TEXT" IS DISTINCT FROM EXCLUDED."TEXT"
                   OR "LICENSE"."TEMPLATE" IS DISTINCT FROM EXCLUDED."TEMPLATE"
                   OR "LICENSE"."ISDEPRECATED" IS DISTINCT FROM EXCLUDED."ISDEPRECATED"
                   OR "LICENSE"."FSFLIBRE" IS DISTINCT FROM EXCLUDED."FSFLIBRE"
                   OR "LICENSE"."ISOSIAPPROVED" IS DISTINCT FROM EXCLUDED."ISOSIAPPROVED"
                   OR "LICENSE"."COMMENT" IS DISTINCT FROM EXCLUDED."COMMENT"
                   OR "LICENSE"."SEEALSO" IS DISTINCT FROM EXCLUDED."SEEALSO"
                """);

        for (final License license : licenses) {
            preparedBatch.bindBean(license);
            preparedBatch.bind(
                    "seeAlsoSerialized",
                    license.getSeeAlso() != null
                            ? SerializationUtils.serialize(license.getSeeAlso())
                            : null);
            preparedBatch.add();
        }

        int licensesCreatedOrUpdated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created or updated {} licenses", licensesCreatedOrUpdated);
    }

    public static void seedDefaultLicenseGroups(final Handle jdbiHandle) {
        final Update update = jdbiHandle.createUpdate("""
                WITH cte_group_license AS (
                  SELECT *
                    FROM UNNEST(:groupNames, :groupRiskWeights, :licenseIds) AS t(group_name, group_risk_weight, license_id)
                ),
                cte_created_group AS (
                  INSERT INTO "LICENSEGROUP" ("NAME", "RISKWEIGHT", "UUID")
                  SELECT DISTINCT ON (group_name)
                         group_name
                       , group_risk_weight
                       , GEN_RANDOM_UUID()
                    FROM cte_group_license
                  RETURNING "ID" AS id, "NAME" AS name
                )
                INSERT INTO "LICENSEGROUP_LICENSE" ("LICENSEGROUP_ID", "LICENSE_ID")
                SELECT cte_created_group.id
                     , (SELECT "ID" FROM "LICENSE" WHERE "LICENSEID" = cte_group_license.license_id)
                  FROM cte_group_license
                 INNER JOIN cte_created_group
                    ON cte_created_group.name = cte_group_license.group_name
                """);

        final JsonArray groupDefsJson;
        try (final InputStream inputStream = DatabaseSeedingInitTask.class.getResourceAsStream("/default-objects/licenseGroups.json");
             final JsonReader jsonReader = Json.createReader(inputStream)) {
            groupDefsJson = jsonReader.readArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse license group definition", e);
        }

        final var groupNames = new ArrayList<String>();
        final var groupRiskWeights = new ArrayList<Integer>();
        final var licenseIds = new ArrayList<String>();

        for (int i = 0; i < groupDefsJson.size(); i++) {
            final JsonObject groupDefJson = groupDefsJson.getJsonObject(i);
            final String groupName = groupDefJson.getString("name");
            final int riskWeight = groupDefJson.getInt("riskWeight");

            final JsonArray licenseIdsJson = groupDefJson.getJsonArray("licenses");
            for (int j = 0; j < licenseIdsJson.size(); j++) {
                groupNames.add(groupName);
                groupRiskWeights.add(riskWeight);
                licenseIds.add(licenseIdsJson.getString(j));
            }
        }

        update
                .bindArray("groupNames", String.class, groupNames)
                .bindArray("groupRiskWeights", Integer.class, groupRiskWeights)
                .bindArray("licenseIds", String.class, licenseIds)
                .execute();
    }

    public static void seedDefaultNotificationPublishers(final Handle jdbiHandle) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "NOTIFICATIONPUBLISHER" (
                  "NAME", "PUBLISHER_CLASS", "DEFAULT_PUBLISHER", "DESCRIPTION"
                , "TEMPLATE", "TEMPLATE_MIME_TYPE", "UUID")
                VALUES (
                  :publisherName, :publisherClass, TRUE, :publisherDescription
                , :templateContent, :templateMimeType, GEN_RANDOM_UUID())
                ON CONFLICT ("NAME") DO UPDATE
                SET "PUBLISHER_CLASS" = EXCLUDED."PUBLISHER_CLASS"
                  , "DESCRIPTION" = EXCLUDED."DESCRIPTION"
                  , "TEMPLATE" = EXCLUDED."TEMPLATE"
                  , "TEMPLATE_MIME_TYPE" =  EXCLUDED."TEMPLATE_MIME_TYPE"
                -- Only update when at least one relevant field has changed.
                WHERE "NOTIFICATIONPUBLISHER"."PUBLISHER_CLASS" IS DISTINCT FROM EXCLUDED."PUBLISHER_CLASS"
                   OR "NOTIFICATIONPUBLISHER"."DESCRIPTION" IS DISTINCT FROM EXCLUDED."DESCRIPTION"
                   OR "NOTIFICATIONPUBLISHER"."TEMPLATE" IS DISTINCT FROM EXCLUDED."TEMPLATE"
                   OR "NOTIFICATIONPUBLISHER"."TEMPLATE_MIME_TYPE" IS DISTINCT FROM EXCLUDED."TEMPLATE_MIME_TYPE"
                """);

        final var configPropertyDao = jdbiHandle.attach(ConfigPropertyDao.class);
        final var templateOverrideEnabled = configPropertyDao.getOptionalValue(
                NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED, Boolean.class).orElse(false);
        final var templateOverrideBaseDir = configPropertyDao.getOptionalValue(
                NOTIFICATION_TEMPLATE_BASE_DIR).orElse(null);
        if (templateOverrideEnabled && templateOverrideBaseDir == null) {
            throw new IllegalStateException("%s is enabled but %s is not configured".formatted(
                    NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getPropertyName(),
                    NOTIFICATION_TEMPLATE_BASE_DIR.getPropertyName()));
        }

        for (final DefaultNotificationPublishers publisher : DefaultNotificationPublishers.values()) {
            final URL templateFileUrl = DatabaseSeedingInitTask.class.getResource(publisher.getPublisherTemplateFile());
            if (templateFileUrl == null) {
                throw new IllegalStateException("Template file %s of default publisher %s does not exist".formatted(
                        publisher.getPublisherTemplateFile(), publisher.getPublisherName()));
            }

            Path templateFilePath;
            try {
                templateFilePath = Paths.get(templateFileUrl.toURI());
            } catch (URISyntaxException e) {
                throw new IllegalStateException("Failed to construct path for template file: " + templateFileUrl, e);
            }

            if (templateOverrideEnabled) {
                final Path customTemplateFilePath = Paths.get(templateOverrideBaseDir, publisher.getPublisherTemplateFile());
                if (Files.exists(customTemplateFilePath)) {
                    templateFilePath = customTemplateFilePath;
                }
            }

            final String templateContent;
            try {
                templateContent = Files.readString(templateFilePath);
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read template file: " + templateFilePath, e);
            }

            preparedBatch.bindBean(publisher);
            preparedBatch.bind("templateContent", templateContent);
            preparedBatch.add();
        }

        final int publishersCreatedOrUpdated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created or updated {} publishers", publishersCreatedOrUpdated);
    }

    public static void seedDefaultRepositories(final Handle jdbiHandle) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "REPOSITORY"(
                  "TYPE", "IDENTIFIER", "URL", "INTERNAL", "RESOLUTION_ORDER"
                , "ENABLED", "AUTHENTICATIONREQUIRED", "UUID")
                VALUES (
                  :type, :identifier, :url, FALSE, :resolutionOrder
                , TRUE, FALSE, GEN_RANDOM_UUID())
                ON CONFLICT ("TYPE", "IDENTIFIER") DO NOTHING
                """);

        for (final DefaultRepository repository : DefaultRepository.values()) {
            preparedBatch.bindBean(repository);
            preparedBatch.add();
        }

        final int reposCreated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created {} repositories", reposCreated);
    }

}
