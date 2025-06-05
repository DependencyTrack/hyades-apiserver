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
import alpine.common.logging.Logger;
import alpine.server.util.DbUtil;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.support.liquibase.MigrationExecutor;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.sql.Connection;
import java.util.Optional;

public class MigrationInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(MigrationInitializer.class);

    private final Config config;

    @SuppressWarnings("unused")
    public MigrationInitializer() {
        this(Config.getInstance());
    }

    MigrationInitializer(final Config config) {
        this.config = config;
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getPropertyAsBoolean(ConfigKey.INIT_TASKS_ENABLED)) {
            LOGGER.debug("Not running migrations because %s is disabled"
                    .formatted(ConfigKey.INIT_TASKS_ENABLED.getPropertyName()));
            return;
        }
        if (!config.getPropertyAsBoolean(ConfigKey.DATABASE_RUN_MIGRATIONS)) {
            LOGGER.debug("Not running migrations because %s is disabled"
                    .formatted(ConfigKey.DATABASE_RUN_MIGRATIONS.getPropertyName()));
            return;
        }

        LOGGER.info("Running migrations");
        try (final HikariDataSource dataSource = createDataSource()) {
            try (final Connection connection = dataSource.getConnection()) {
                // Ensure that DbUtil#isPostgreSQL will work as expected.
                // Some legacy code ported over from v4 still uses this.
                //
                // NB: This was previously done in alpine.server.upgrade.UpgradeExecutor.
                //
                // TODO: Remove once DbUtil#isPostgreSQL is no longer used.
                DbUtil.initPlatformName(connection);
            }

            new MigrationExecutor(dataSource, "migration/changelog-main.xml").executeMigration();
        } catch (Exception e) {
            if (config.getPropertyAsBoolean(ConfigKey.DATABASE_RUN_MIGRATIONS_ONLY)
                || config.getPropertyAsBoolean(ConfigKey.INIT_AND_EXIT)) {
                // Make absolutely sure that we exit with non-zero code so
                // the container orchestrator knows to restart the container.
                LOGGER.error("Failed to execute migrations", e);
                System.exit(1);
            }

            throw new RuntimeException("Failed to execute migrations", e);
        }

        if (config.getPropertyAsBoolean(ConfigKey.DATABASE_RUN_MIGRATIONS_ONLY)) {
            LOGGER.info("Exiting because %s is enabled".formatted(ConfigKey.DATABASE_RUN_MIGRATIONS.getPropertyName()));
            System.exit(0);
        }
    }

    private HikariDataSource createDataSource() {
        final String jdbcUrl = Optional.ofNullable(config.getProperty(ConfigKey.DATABASE_MIGRATION_URL))
                .orElseGet(() -> config.getProperty(Config.AlpineKey.DATABASE_URL));
        final String username = Optional.ofNullable(config.getProperty(ConfigKey.DATABASE_MIGRATION_USERNAME))
                .orElseGet(() -> config.getProperty(Config.AlpineKey.DATABASE_USERNAME));
        final String password = Optional.ofNullable(config.getProperty(ConfigKey.DATABASE_MIGRATION_PASSWORD))
                .orElseGet(() -> config.getProperty(Config.AlpineKey.DATABASE_PASSWORD));

        final var hikariCfg = new HikariConfig();
        hikariCfg.setJdbcUrl(jdbcUrl);
        hikariCfg.setDriverClassName(config.getProperty(Config.AlpineKey.DATABASE_DRIVER));
        hikariCfg.setUsername(username);
        hikariCfg.setPassword(password);
        hikariCfg.setMaximumPoolSize(1);
        hikariCfg.setMinimumIdle(1);

        return new HikariDataSource(hikariCfg);
    }
}
