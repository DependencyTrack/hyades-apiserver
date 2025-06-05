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
package org.dependencytrack.support.liquibase;

import liquibase.Liquibase;
import liquibase.Scope;
import liquibase.UpdateSummaryOutputEnum;
import liquibase.analytics.configuration.AnalyticsArgs;
import liquibase.command.CommandScope;
import liquibase.command.core.UpdateCommandStep;
import liquibase.command.core.helpers.DbUrlConnectionArgumentsCommandStep;
import liquibase.command.core.helpers.ShowSummaryArgument;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;
import liquibase.ui.LoggerUIService;

import javax.sql.DataSource;
import java.util.HashMap;

/**
 * @since 5.6.0
 */
public class MigrationExecutor {

    private final DataSource dataSource;
    private final String changelogResourcePath;
    private String changeLogTableName;
    private String changeLogLockTableName;

    public MigrationExecutor(final DataSource dataSource, final String changelogResourcePath) {
        this.dataSource = dataSource;
        this.changelogResourcePath = changelogResourcePath;
    }

    public MigrationExecutor withChangeLogTableName(final String changeLogTableName) {
        this.changeLogTableName = changeLogTableName;
        return this;
    }

    public MigrationExecutor withChangeLogLockTableName(final String changeLogLockTableName) {
        this.changeLogLockTableName = changeLogLockTableName;
        return this;
    }

    public void executeMigration() throws Exception {
        final var scopeAttributes = new HashMap<String, Object>();
        scopeAttributes.put(AnalyticsArgs.ENABLED.getKey(), false);
        scopeAttributes.put(Scope.Attr.logService.name(), new LiquibaseLogger.LogService());
        scopeAttributes.put(Scope.Attr.ui.name(), new LoggerUIService());

        Scope.child(scopeAttributes, () -> {
            final Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(dataSource.getConnection()));
            if (changeLogTableName != null) {
                database.setDatabaseChangeLogTableName(changeLogTableName);
            }
            if (changeLogLockTableName != null) {
                database.setDatabaseChangeLogLockTableName(changeLogLockTableName);
            }
            final var liquibase = new Liquibase(changelogResourcePath, new ClassLoaderResourceAccessor(), database);

            final var updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME);
            updateCommand.addArgumentValue(DbUrlConnectionArgumentsCommandStep.DATABASE_ARG, liquibase.getDatabase());
            updateCommand.addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, liquibase.getChangeLogFile());
            updateCommand.addArgumentValue(ShowSummaryArgument.SHOW_SUMMARY_OUTPUT, UpdateSummaryOutputEnum.LOG);
            updateCommand.execute();
        });
    }

}
