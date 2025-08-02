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

import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowEngineFactory;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.util.ServiceLoader;
import java.util.UUID;

import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_MIGRATION_PASSWORD;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_MIGRATION_URL;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_MIGRATION_USERNAME;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_PASSWORD;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_URL;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_USERNAME;

public class WorkflowEngineDatabaseMigrationInitTask implements InitTask {

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
        if (!ctx.config().getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_ENABLED)) {
            return;
        }

        final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), getDataSource(ctx));
        final var engineFactory = ServiceLoader.load(WorkflowEngineFactory.class).findFirst().orElseThrow();

        try (final WorkflowEngine engine = engineFactory.create(engineConfig)) {
            engine.migrateDatabase();
        }
    }

    private DataSource getDataSource(final InitTaskContext ctx) {
        String engineDbUrl = ctx.config().getProperty(WORKFLOW_ENGINE_DATABASE_MIGRATION_URL);
        if (engineDbUrl != null) {
            final var dataSource = new PGSimpleDataSource();
            dataSource.setUrl(engineDbUrl);
            dataSource.setUser(ctx.config().getProperty(WORKFLOW_ENGINE_DATABASE_MIGRATION_USERNAME));
            dataSource.setPassword(ctx.config().getProperty(WORKFLOW_ENGINE_DATABASE_MIGRATION_PASSWORD));
            return dataSource;
        }

        engineDbUrl = ctx.config().getProperty(WORKFLOW_ENGINE_DATABASE_URL);
        if (engineDbUrl != null) {
            final var dataSource = new PGSimpleDataSource();
            dataSource.setUrl(engineDbUrl);
            dataSource.setUser(ctx.config().getProperty(WORKFLOW_ENGINE_DATABASE_USERNAME));
            dataSource.setPassword(ctx.config().getProperty(WORKFLOW_ENGINE_DATABASE_PASSWORD));
            return dataSource;
        }

        return ctx.dataSource();
    }

}
