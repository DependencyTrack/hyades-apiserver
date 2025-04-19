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
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.connection.ConnectionManagerImpl;
import org.datanucleus.store.rdbms.ConnectionFactoryImpl;
import org.datanucleus.store.rdbms.RDBMSStoreManager;
import org.dependencytrack.workflow.engine.WorkflowEngine;
import org.dependencytrack.workflow.engine.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.persistence.Migration;
import org.glassfish.hk2.api.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import javax.jdo.PersistenceManagerFactory;
import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.UUID;

import static alpine.Config.AlpineKey.DATABASE_POOL_MAX_SIZE;
import static alpine.Config.AlpineKey.DATABASE_POOL_MIN_IDLE;
import static org.apache.commons.lang3.reflect.FieldUtils.readField;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_BUFFER_EXTERNAL_EVENT_FLUSH_INTERVAL_MS;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_BUFFER_EXTERNAL_EVENT_MAX_BATCH_SIZE;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_BUFFER_TASK_COMMAND_FLUSH_INTERVAL_MS;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_DATABASE_PASSWORD;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_DATABASE_RUN_MIGRATIONS;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_DATABASE_URL;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_DATABASE_USERNAME;
import static org.dependencytrack.workflow.WorkflowConfigKey.ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS;

final class WorkflowEngineFactory implements Factory<WorkflowEngine> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineFactory.class);

    private final Config config;
    private final PersistenceManagerFactory pmf;

    @Inject
    public WorkflowEngineFactory(final Config config, final PersistenceManagerFactory pmf) {
        this.config = config;
        this.pmf = pmf;
    }

    @Override
    public WorkflowEngine provide() {
        DataSource dataSource = getConfiguredDataSource(config);
        if (dataSource == null) {
            LOGGER.debug("No dedicated database configured; Using application database");
            dataSource = extractDataSource(pmf);
        }

        if (config.getPropertyAsBoolean(ENGINE_DATABASE_RUN_MIGRATIONS)) {
            Migration.run(dataSource);
        } else if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "Not running migrations because {} is disabled",
                    ENGINE_DATABASE_RUN_MIGRATIONS.getPropertyName());
        }

        final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);
        engineConfig.activityTaskDispatcher().setMinPollInterval(
                Duration.ofMillis(config.getPropertyAsInt(ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS)));
        engineConfig.workflowTaskDispatcher().setMinPollInterval(
                Duration.ofMillis(config.getPropertyAsInt(ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS)));
        engineConfig.externalEventBuffer().setFlushInterval(
                Duration.ofMillis(config.getPropertyAsInt(ENGINE_BUFFER_EXTERNAL_EVENT_FLUSH_INTERVAL_MS)));
        engineConfig.externalEventBuffer().setMaxBatchSize(
                config.getPropertyAsInt(ENGINE_BUFFER_EXTERNAL_EVENT_MAX_BATCH_SIZE));
        engineConfig.taskCommandBuffer().setFlushInterval(
                Duration.ofMillis(config.getPropertyAsInt(ENGINE_BUFFER_TASK_COMMAND_FLUSH_INTERVAL_MS)));
        engineConfig.taskCommandBuffer().setMaxBatchSize(
                config.getPropertyAsInt(WorkflowConfigKey.ENGINE_BUFFER_TASK_COMMAND_MAX_BATCH_SIZE));

        final var engine = new WorkflowEngine(engineConfig);
        engine.start();

        return engine;
    }

    @Override
    public void dispose(final WorkflowEngine instance) {
        try {
            instance.close();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to close workflow engine", e);
        }
    }

    private static DataSource getConfiguredDataSource(final Config config) {
        final String configuredDatabaseUrl = config.getProperty(ENGINE_DATABASE_URL);
        if (configuredDatabaseUrl == null) {
            return null;
        }

        final var hikariConfig = new HikariConfig();
        hikariConfig.setDriverClassName(org.postgresql.Driver.class.getName());
        hikariConfig.setJdbcUrl(configuredDatabaseUrl);
        hikariConfig.setUsername(config.getProperty(ENGINE_DATABASE_USERNAME));
        hikariConfig.setPassword(config.getProperty(ENGINE_DATABASE_PASSWORD));
        // TODO: Some more pool properties?

        // TODO: Use pool properties specific to workflow engine.
        hikariConfig.setMaximumPoolSize(config.getPropertyAsInt(DATABASE_POOL_MAX_SIZE));
        hikariConfig.setMinimumIdle(config.getPropertyAsInt(DATABASE_POOL_MIN_IDLE));
        return new HikariDataSource(hikariConfig);
    }

    private static DataSource extractDataSource(final PersistenceManagerFactory pmf) {
        try {
            if (pmf instanceof final JDOPersistenceManagerFactory jdoPmf
                && jdoPmf.getNucleusContext().getStoreManager() instanceof final RDBMSStoreManager storeManager
                && storeManager.getConnectionManager() instanceof final ConnectionManagerImpl connectionManager
                && readField(connectionManager, "primaryConnectionFactory", true) instanceof ConnectionFactoryImpl connectionFactory
                && readField(connectionFactory, "dataSource", true) instanceof final DataSource dataSource) {
                return dataSource;
            }
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Failed to access datasource of PMF via reflection", e);
        }

        throw new IllegalStateException("Failed to access primary datasource of PMF");
    }

}
