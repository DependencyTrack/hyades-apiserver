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

import alpine.Config;
import alpine.server.util.DbUtil;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.support.liquibase.MigrationExecutor;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.sql.Connection;

import static java.util.Objects.requireNonNullElseGet;

/**
 * @since 5.6.0
 */
public final class DatabaseMigrationInitTask implements InitTask {

    @Override
    public int priority() {
        return PRIORITY_HIGHEST;
    }

    @Override
    public String name() {
        return "database-migration";
    }

    @Override
    public void execute(InitTaskContext ctx) throws Exception {
        final DataSource dataSource =
                ctx.config().getProperty(ConfigKey.DATABASE_MIGRATION_URL) != null
                        ? createMigrationDataSource(ctx.config())
                        : ctx.dataSource();

        try (final Connection connection = dataSource.getConnection()) {
            // Ensure that DbUtil#isPostgreSQL will work as expected.
            // Some legacy code ported over from v4 still uses this.
            //
            // NB: This was previously done in alpine.server.upgrade.UpgradeExecutor.
            //
            // TODO: Remove once DbUtil#isPostgreSQL is no longer used.
            DbUtil.initPlatformName(connection);
        }

        new MigrationExecutor(ctx.dataSource(), "migration/changelog-main.xml").executeMigration();
    }

    private DataSource createMigrationDataSource(final Config config) {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(config.getProperty(ConfigKey.DATABASE_MIGRATION_URL));
        dataSource.setUser(requireNonNullElseGet(
                config.getProperty(ConfigKey.DATABASE_MIGRATION_USERNAME),
                () -> config.getProperty(Config.AlpineKey.DATABASE_USERNAME)));
        dataSource.setPassword(requireNonNullElseGet(
                config.getProperty(ConfigKey.DATABASE_MIGRATION_PASSWORD),
                () -> config.getProperty(Config.AlpineKey.DATABASE_PASSWORD)));

        return dataSource;
    }

}
