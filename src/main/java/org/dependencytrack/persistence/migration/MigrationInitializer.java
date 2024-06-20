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
package org.dependencytrack.persistence.migration;

import alpine.Config;
import alpine.common.logging.Logger;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import liquibase.Liquibase;
import liquibase.Scope;
import liquibase.UpdateSummaryOutputEnum;
import liquibase.command.CommandScope;
import liquibase.command.core.UpdateCommandStep;
import liquibase.command.core.helpers.DbUrlConnectionArgumentsCommandStep;
import liquibase.command.core.helpers.ShowSummaryArgument;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;
import liquibase.ui.LoggerUIService;
import org.dependencytrack.common.ConfigKey;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.sql.DataSource;
import java.util.HashMap;
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
        if (!config.getPropertyAsBoolean(ConfigKey.DATABASE_RUN_MIGRATIONS)) {
            LOGGER.info("Migrations are disabled; Skipping");
            return;
        }

        LOGGER.info("Running migrations");
        try (final HikariDataSource dataSource = createDataSource()) {
            runMigration(dataSource);
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute migrations", e);
        }
    }

    public static void runMigration(final DataSource dataSource) throws Exception {
        runMigration(dataSource, "migration/changelog-main.xml");
    }

    public static void runMigration(final DataSource dataSource, final String changelogResourcePath) throws Exception {
        final var scopeAttributes = new HashMap<String, Object>();
        scopeAttributes.put(Scope.Attr.logService.name(), new LiquibaseLogger.LogService());
        scopeAttributes.put(Scope.Attr.ui.name(), new LoggerUIService());

        Scope.child(scopeAttributes, () -> {
            final Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(dataSource.getConnection()));
            final var liquibase = new Liquibase(changelogResourcePath, new ClassLoaderResourceAccessor(), database);

            final var updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME);
            updateCommand.addArgumentValue(DbUrlConnectionArgumentsCommandStep.DATABASE_ARG, liquibase.getDatabase());
            updateCommand.addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, liquibase.getChangeLogFile());
            updateCommand.addArgumentValue(ShowSummaryArgument.SHOW_SUMMARY_OUTPUT, UpdateSummaryOutputEnum.LOG);
            updateCommand.execute();
        });
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
