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

import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.workflow.engine.migration.MigrationExecutor;
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
    public void execute(final InitTaskContext ctx) {
        if (!ctx.config().getOptionalValue("dt.workflow-engine.enabled", boolean.class).orElse(false)) {
            LOGGER.info("Skipping execution because workflow engine is disabled");
            return;
        }

        final String dataSourceName = ctx.config().getValue("dt.workflow-engine.migration.datasource.name", String.class);
        final DataSource dataSource = DataSourceRegistry.getInstance().get(dataSourceName);

        new MigrationExecutor(dataSource).execute();
    }

}
