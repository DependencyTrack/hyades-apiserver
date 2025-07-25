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
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowEngineFactory;

import java.util.ServiceLoader;
import java.util.UUID;

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
        // TODO: The workflow engine could have a separate database. Construct a new DataSource if needed.
        final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), ctx.dataSource());
        final var engineFactory = ServiceLoader.load(WorkflowEngineFactory.class).findFirst().orElseThrow();

        try (final WorkflowEngine engine = engineFactory.create(engineConfig)) {
            engine.migrateDatabase();
        }
    }

}
