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
package org.dependencytrack.workflow;

import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.workflow.engine.migration.MigrationExecutor;
import org.postgresql.ds.PGSimpleDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;

/**
 * @since 5.7.0
 */
public final class WorkflowEngineDatabaseMigrationInitTask implements InitTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineDatabaseMigrationInitTask.class);

    @Override
    public int priority() {
        return PRIORITY_HIGHEST - 5;
    }

    @Override
    public String name() {
        return "workflow.engine.database.migration";
    }

    @Override
    public void execute(final InitTaskContext ctx) throws Exception {
        if (!ctx.config().getOptionalValue("workflow-engine.enabled", boolean.class).orElse(false)) {
            LOGGER.info("Skipping execution because workflow engine is disabled");
            return;
        }

        new MigrationExecutor(getDataSource(ctx)).executeMigration();
    }

    private DataSource getDataSource(final InitTaskContext ctx) {
        String engineDbUrl = ctx.config().getOptionalValue("workflow-engine.database.migration-url", String.class).orElse(null);
        if (engineDbUrl != null) {
            final var dataSource = new PGSimpleDataSource();
            dataSource.setUrl(engineDbUrl);
            dataSource.setUser(ctx.config().getOptionalValue("workflow-engine.database.migration-username", String.class).orElse(null));
            dataSource.setPassword(ctx.config().getOptionalValue("workflow-engine.database.migration-password", String.class).orElse(null));
            return dataSource;
        }

        engineDbUrl = ctx.config().getOptionalValue("workflow-engine.database.url", String.class).orElse(null);
        if (engineDbUrl != null) {
            final var dataSource = new PGSimpleDataSource();
            dataSource.setUrl(engineDbUrl);
            dataSource.setUser(ctx.config().getOptionalValue("workflow-engine.database.username", String.class).orElse(null));
            dataSource.setPassword(ctx.config().getOptionalValue("workflow-engine.database.password", String.class).orElse(null));
            return dataSource;
        }

        return ctx.dataSource();
    }

}
