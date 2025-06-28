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

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.License;
import org.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Update;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_DEFAULT_OBJECTS_VERSION;

/**
 * @since 5.6.0
 */
public final class DatabaseSeedingInitTask implements InitTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseSeedingInitTask.class);

    @Override
    public int priority() {
        return 1;
    }

    @Override
    public String name() {
        return "database-seeding";
    }

    @Override
    public void execute(final InitTaskContext ctx) throws Exception {
        final var jdbi = JdbiFactory.createLocalJdbi(ctx.dataSource());

        jdbi.useTransaction(handle -> {
            final boolean shouldExecute =
                    handle.attach(ConfigPropertyDao.class)
                            .getOptionalValue(INTERNAL_DEFAULT_OBJECTS_VERSION)
                            .map(ctx.config().getApplicationBuildUuid()::equals)
                            .orElse(true);
            if (!shouldExecute) {
                LOGGER.info(
                        "Default objects already populated for build {} (timestamp: {}); Skipping",
                        ctx.config().getApplicationBuildUuid(),
                        ctx.config().getApplicationBuildTimestamp());
                return;
            }

            seedDefaultConfigProperties(handle);
            seedDefaultPermissions(handle);
            seedDefaultPersonas(handle);
            seedDefaultLicenses(handle);
        });
    }

    private void seedDefaultConfigProperties(final Handle jdbiHandle) {
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "CONFIGPROPERTY" ("GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE", "DESCRIPTION")
                SELECT *
                  FROM UNNEST(:groups, :names, :types, :values, :descriptions)
                ON CONFLICT ("GROUPNAME", "PROPERTYNAME") DO NOTHING
                """);

        final int propertyCount = ConfigPropertyConstants.values().length;
        final var groups = new ArrayList<String>(propertyCount);
        final var names = new ArrayList<String>(propertyCount);
        final var types = new ArrayList<String>(propertyCount);
        final var values = new ArrayList<String>(propertyCount);
        final var descriptions = new ArrayList<String>(propertyCount);

        for (final ConfigPropertyConstants configProperty : ConfigPropertyConstants.values()) {
            groups.add(configProperty.getGroupName());
            names.add(configProperty.getPropertyName());
            types.add(configProperty.getPropertyType().name());
            values.add(configProperty.getDefaultPropertyValue());
            descriptions.add(configProperty.getDescription());
        }

        final int configPropertiesCreated = update
                .bindArray("groups", String.class, groups)
                .bindArray("names", String.class, names)
                .bindArray("types", String.class, types)
                .bindArray("values", String.class, values)
                .bindArray("descriptions", String.class, descriptions)
                .execute();
        LOGGER.debug("Created {} config properties", configPropertiesCreated);
    }

    private void seedDefaultPermissions(final Handle jdbiHandle) {
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "PERMISSION" ("NAME", "DESCRIPTION")
                SELECT *
                  FROM UNNEST(:names, :descriptions)
                ON CONFLICT ("NAME") DO NOTHING
                """);

        final var names = new ArrayList<String>(Permissions.values().length);
        final var descriptions = new ArrayList<String>(Permissions.values().length);

        for (final Permissions permission : Permissions.values()) {
            names.add(permission.name());
            descriptions.add(permission.getDescription());
        }

        final int permissionsCreated = update
                .bindArray("names", String.class, names)
                .bindArray("descriptions", String.class, descriptions)
                .execute();
        LOGGER.debug("Created {} permissions", permissionsCreated);
    }

    private void seedDefaultPersonas(final Handle jdbiHandle) {
        // TODO
    }

    public static void seedDefaultLicenses(final Handle jdbiHandle) {
        final SpdxLicenseDetailParser parser = new SpdxLicenseDetailParser();
        final List<License> licenses;
        try {
            licenses = parser.getLicenseDefinitions();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "LICENSE" (
                  "LICENSEID"
                , "NAME"
                , "HEADER"
                , "TEXT"
                , "TEMPLATE"
                , "ISDEPRECATED"
                , "FSFLIBRE"
                , "ISOSIAPPROVED"
                , "COMMENT"
                , "UUID"
                )
                SELECT *
                  FROM UNNEST(
                         :ids
                       , :names
                       , :headers
                       , :texts
                       , :templates
                       , :isDeprecateds
                       , :isFsfLibres
                       , :isOsiApproveds
                       , :comments
                       , :uuids
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
                WHERE "LICENSE"."NAME" IS DISTINCT FROM EXCLUDED."NAME"
                   OR "LICENSE"."HEADER" IS DISTINCT FROM EXCLUDED."HEADER"
                   OR "LICENSE"."TEXT" IS DISTINCT FROM EXCLUDED."TEXT"
                   OR "LICENSE"."TEMPLATE" IS DISTINCT FROM EXCLUDED."TEMPLATE"
                   OR "LICENSE"."ISDEPRECATED" IS DISTINCT FROM EXCLUDED."ISDEPRECATED"
                   OR "LICENSE"."FSFLIBRE" IS DISTINCT FROM EXCLUDED."FSFLIBRE"
                   OR "LICENSE"."ISOSIAPPROVED" IS DISTINCT FROM EXCLUDED."ISOSIAPPROVED"
                   OR "LICENSE"."COMMENT" IS DISTINCT FROM EXCLUDED."COMMENT"
                """);

        final var ids = new ArrayList<String>(licenses.size());
        final var names  = new ArrayList<String>(licenses.size());
        final var headers = new ArrayList<String>(licenses.size());
        final var texts  = new ArrayList<String>(licenses.size());
        final var templates = new ArrayList<String>(licenses.size());
        final var isDeprecateds  = new ArrayList<Boolean>(licenses.size());
        final var isFsfLibres = new ArrayList<Boolean>(licenses.size());
        final var isOsiApproveds = new ArrayList<Boolean>(licenses.size());
        final var comments = new ArrayList<String>(licenses.size());
        final var uuids = new ArrayList<UUID>(licenses.size());

        for (final License license : licenses) {
            ids.add(license.getLicenseId());
            names.add(license.getName());
            headers.add(license.getHeader());
            texts.add(license.getText());
            templates.add(license.getTemplate());
            isDeprecateds.add(license.isDeprecatedLicenseId());
            isFsfLibres.add(license.isFsfLibre());
            isOsiApproveds.add(license.isOsiApproved());
            comments.add(license.getComment());
            uuids.add(UUID.randomUUID());
        }

        final int licensesCreated = update
                .bindArray("ids", String.class, ids)
                .bindArray("names", String.class, names)
                .bindArray("headers", String.class, headers)
                .bindArray("texts", String.class, texts)
                .bindArray("templates", String.class, templates)
                .bindArray("isDeprecateds", Boolean.class, isDeprecateds)
                .bindArray("isFsfLibres", Boolean.class, isFsfLibres)
                .bindArray("isOsiApproveds", Boolean.class, isOsiApproveds)
                .bindArray("comments", String.class, comments)
                .bindArray("uuids", UUID.class, uuids)
                .execute();
        LOGGER.debug("Created {} licenses", licensesCreated);
    }

}
