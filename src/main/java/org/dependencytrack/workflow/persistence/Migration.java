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
package org.dependencytrack.workflow.persistence;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.util.HashMap;

public class Migration {

    private static final Logger LOGGER = LoggerFactory.getLogger(Migration.class);

    public static void run(final DataSource dataSource) {
        final var scopeAttributes = new HashMap<String, Object>();
        scopeAttributes.put(AnalyticsArgs.ENABLED.getKey(), false);
        scopeAttributes.put(Scope.Attr.ui.name(), new LoggerUIService());

        try {
            Scope.child(scopeAttributes, () -> {
                final Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(dataSource.getConnection()));
                // NB: Changelog table names must be different in case the migration
                // executes in the main database.
                database.setDatabaseChangeLogTableName("workflow_database_changelog");
                database.setDatabaseChangeLogLockTableName("workflow_database_changelog_lock");
                final var liquibase = new Liquibase("workflow/migration/changelog.xml", new ClassLoaderResourceAccessor(), database);

                final var updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME);
                updateCommand.addArgumentValue(DbUrlConnectionArgumentsCommandStep.DATABASE_ARG, liquibase.getDatabase());
                updateCommand.addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, liquibase.getChangeLogFile());
                updateCommand.addArgumentValue(ShowSummaryArgument.SHOW_SUMMARY_OUTPUT, UpdateSummaryOutputEnum.LOG);
                updateCommand.execute();
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
