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
import alpine.common.metrics.Metrics;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.metrics.micrometer.MicrometerMetricsTrackerFactory;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowEngineFactory;
import org.postgresql.ds.PGSimpleDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.ServiceLoader;
import java.util.UUID;

import static alpine.Config.AlpineKey.DATABASE_PASSWORD;
import static alpine.Config.AlpineKey.DATABASE_URL;
import static alpine.Config.AlpineKey.DATABASE_USERNAME;
import static alpine.Config.AlpineKey.METRICS_ENABLED;
import static java.util.Objects.requireNonNullElseGet;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_ACTIVITY_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_PASSWORD;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_POOL_ENABLED;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_POOL_MAX_SIZE;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_POOL_MIN_IDLE;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_URL;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_USERNAME;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_RETENTION_DAYS;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_TASK_COMMAND_BUFFER_FLUSH_INTERVAL_MS;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_TASK_COMMAND_BUFFER_MAX_SIZE;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS;

/**
 * @since 5.7.0
 */
public class WorkflowEngineInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineInitializer.class);

    private final Config config = Config.getInstance();
    private WorkflowEngine engine;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_ENABLED)) {
            return;
        }

        final WorkflowEngineConfig engineConfig = createEngineConfig(config);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Effective configuration: {}", engineConfig);
        }

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

    private static WorkflowEngineConfig createEngineConfig(final Config config) {
        final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), createDataSource(config));

        engineConfig.activityTaskDispatcher().setMinPollInterval(
                Duration.ofMillis(config.getPropertyAsInt(
                        WORKFLOW_ENGINE_ACTIVITY_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS)));
        // TODO: Backoff config

        if (config.getPropertyAsBoolean(METRICS_ENABLED)) {
            engineConfig.setMeterRegistry(Metrics.getRegistry());
        }

        engineConfig.retention().setDays(config.getPropertyAsInt(
                WORKFLOW_ENGINE_RETENTION_DAYS));

        engineConfig.taskCommandBuffer().setFlushInterval(
                Duration.ofMillis(config.getPropertyAsInt(
                        WORKFLOW_ENGINE_TASK_COMMAND_BUFFER_FLUSH_INTERVAL_MS)));
        engineConfig.taskCommandBuffer().setMaxBatchSize(config.getPropertyAsInt(
                WORKFLOW_ENGINE_TASK_COMMAND_BUFFER_MAX_SIZE));

        engineConfig.workflowTaskDispatcher().setMinPollInterval(
                Duration.ofMillis(config.getPropertyAsInt(
                        WORKFLOW_ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS)));
        // TODO: Backoff config

        return engineConfig;
    }

    private static DataSource createDataSource(final Config config) {
        final String url = requireNonNullElseGet(
                config.getProperty(WORKFLOW_ENGINE_DATABASE_URL),
                () -> config.getProperty(DATABASE_URL));
        final String username = requireNonNullElseGet(
                config.getProperty(WORKFLOW_ENGINE_DATABASE_USERNAME),
                () -> config.getProperty(DATABASE_USERNAME));
        final String password = requireNonNullElseGet(
                config.getProperty(WORKFLOW_ENGINE_DATABASE_PASSWORD),
                () -> config.getProperty(DATABASE_PASSWORD));

        if (config.getPropertyAsBoolean(WORKFLOW_ENGINE_DATABASE_POOL_ENABLED)) {
            final var hikariConfig = new HikariConfig();
            hikariConfig.setPoolName("workflow-engine");
            hikariConfig.setJdbcUrl(url);
            hikariConfig.setDriverClassName(org.postgresql.Driver.class.getName());
            hikariConfig.setUsername(username);
            hikariConfig.setPassword(password);
            hikariConfig.setMaximumPoolSize(config.getPropertyAsInt(WORKFLOW_ENGINE_DATABASE_POOL_MAX_SIZE));
            hikariConfig.setMinimumIdle(config.getPropertyAsInt(WORKFLOW_ENGINE_DATABASE_POOL_MIN_IDLE));

            if (config.getPropertyAsBoolean(METRICS_ENABLED)) {
                hikariConfig.setMetricsTrackerFactory(
                        new MicrometerMetricsTrackerFactory(Metrics.getRegistry()));
            }

            return new HikariDataSource(hikariConfig);
        }

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(url);
        dataSource.setUser(username);
        dataSource.setPassword(password);
        return dataSource;
    }

}
