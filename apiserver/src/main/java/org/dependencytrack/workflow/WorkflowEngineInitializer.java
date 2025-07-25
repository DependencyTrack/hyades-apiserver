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

import alpine.Config;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowEngineFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import javax.sql.DataSource;
import java.io.IOException;
import java.util.ServiceLoader;
import java.util.UUID;

public class WorkflowEngineInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineInitializer.class);

    private final Config config = Config.getInstance();
    private WorkflowEngine engine;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_ENABLED)) {
            return;
        }

        // TODO: The workflow engine could have a separate database. Construct a new DataSource if needed.
        final DataSource dataSource;
        try (final var qm = new QueryManager()) {
            dataSource = PersistenceUtil.getDataSource(
                    qm.getPersistenceManager().getPersistenceManagerFactory());
        }

        final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);
        final var engineFactory = ServiceLoader.load(WorkflowEngineFactory.class).findFirst().orElseThrow();
        engine = engineFactory.create(engineConfig);
        engine.start();

        WorkflowEngineHolder.set(engine);
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (engine == null) {
            return;
        }

        try {
            engine.close();
        } catch (IOException e) {
            LOGGER.error("Failed to stop engine", e);
        }
    }

}
