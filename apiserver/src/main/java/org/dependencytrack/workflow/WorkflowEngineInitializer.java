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

import alpine.common.metrics.Metrics;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowEngineFactory;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.ServiceLoader;
import java.util.UUID;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;

/**
 * @since 5.7.0
 */
public final class WorkflowEngineInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowEngineInitializer.class);

    private final Config config;
    private WorkflowEngine engine;

    public WorkflowEngineInitializer() {
        this.config = ConfigProvider.getConfig();
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getOptionalValue("workflow-engine.enabled", Boolean.class).orElse(false)) {
            return;
        }

        final WorkflowEngineConfig engineConfig = createEngineConfig(config);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Effective configuration: {}", engineConfig);
        }

        final var engineFactory = ServiceLoader.load(WorkflowEngineFactory.class).findFirst().orElseThrow();
        engine = engineFactory.create(engineConfig);
        WorkflowEngineHolder.set(engine);

        LOGGER.info("Starting workflow engine");
        engine.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (engine == null) {
            return;
        }

        LOGGER.info("Stopping workflow engine");
        try {
            engine.close();
        } catch (IOException e) {
            LOGGER.error("Failed to stop engine", e);
        }
    }

    WorkflowEngine getEngine() {
        return engine;
    }

    private static WorkflowEngineConfig createEngineConfig(final Config config) {
        final String dataSourceName = config.getValue("workflow-engine.datasource.name", String.class);
        final DataSource dataSource = DataSourceRegistry.getInstance().get(dataSourceName);

        final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);

        config.getOptionalValue("workflow-engine.cache.run-history.max-size", int.class)
                .ifPresent(engineConfig.runHistoryCache()::setMaxSize);
        config.getOptionalValue("workflow-engine.cache.run-history.ttl", Duration.class)
                .ifPresent(engineConfig.runHistoryCache()::setEvictAfterAccess);

        config.getOptionalValue("workflow-engine.buffer.external-event.flush-interval", Duration.class)
                .ifPresent(engineConfig.externalEventBuffer()::setFlushInterval);
        config.getOptionalValue("workflow-engine.buffer.external-event.max-size", int.class)
                .ifPresent(engineConfig.externalEventBuffer()::setMaxBatchSize);

        config.getOptionalValue("workflow-engine.buffer.task-command.flush-interval", Duration.class)
                .ifPresent(engineConfig.taskCommandBuffer()::setFlushInterval);
        config.getOptionalValue("workflow-engine.buffer.task-command.max-size", int.class)
                .ifPresent(engineConfig.taskCommandBuffer()::setMaxBatchSize);

        config.getOptionalValue("workflow-engine.retention.enabled", boolean.class)
                .ifPresent(engineConfig.retention()::setWorkerEnabled);
        config.getOptionalValue("workflow-engine.retention.days", int.class)
                .ifPresent(engineConfig.retention()::setDays);

        config.getOptionalValue("workflow-engine.task-dispatcher.activity.min-poll-interval", Duration.class)
                .ifPresent(engineConfig.activityTaskDispatcher()::setMinPollInterval);
        engineConfig.activityTaskDispatcher().setPollBackoffIntervalFunction(ofExponentialRandomBackoff(
                config.getOptionalValue("workflow-engine.task-dispatcher.activity.poll-backoff.initial-delay", Duration.class).orElseGet(() -> Duration.ofMillis(100)),
                config.getOptionalValue("workflow-engine.task-dispatcher.activity.poll-backoff.multiplier", double.class).orElse(1.5),
                config.getOptionalValue("workflow-engine.task-dispatcher.activity.poll-backoff.randomization-factor", double.class).orElse(0.3),
                config.getOptionalValue("workflow-engine.task-dispatcher.activity.poll-backoff.max-delay", Duration.class).orElseGet(() -> Duration.ofSeconds(3))));

        config.getOptionalValue("workflow-engine.task-dispatcher.workflow.min-poll-interval", Duration.class)
                .ifPresent(engineConfig.workflowTaskDispatcher()::setMinPollInterval);
        engineConfig.workflowTaskDispatcher().setPollBackoffIntervalFunction(ofExponentialRandomBackoff(
                config.getOptionalValue("workflow-engine.task-dispatcher.workflow.poll-backoff.initial-delay", Duration.class).orElseGet(() -> Duration.ofMillis(100)),
                config.getOptionalValue("workflow-engine.task-dispatcher.workflow.poll-backoff.multiplier", double.class).orElse(1.5),
                config.getOptionalValue("workflow-engine.task-dispatcher.workflow.poll-backoff.randomization-factor", double.class).orElse(0.3),
                config.getOptionalValue("workflow-engine.task-dispatcher.workflow.poll-backoff.max-delay", Duration.class).orElseGet(() -> Duration.ofSeconds(3))));

        if (config.getOptionalValue("alpine.metrics.enabled", boolean.class).orElse(false)) {
            engineConfig.setMeterRegistry(Metrics.getRegistry());
        }

        return engineConfig;
    }

}
