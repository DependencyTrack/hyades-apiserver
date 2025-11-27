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
package org.dependencytrack.dex;

import io.micrometer.core.instrument.Metrics;
import io.smallrye.config.SmallRyeConfig;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.EncryptedPageTokenEncoder;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.DexEngineConfigMapping.TaskWorkerConfigMapping;
import org.dependencytrack.dex.engine.api.ActivityTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.DexEngineFactory;
import org.dependencytrack.dex.engine.api.TaskQueueType;
import org.dependencytrack.dex.engine.api.WorkflowTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.util.ServiceLoader;
import java.util.UUID;

/**
 * @since 5.7.0
 */
public final class DexEngineInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(DexEngineInitializer.class);

    private final Config config;
    private final DataSourceRegistry dataSourceRegistry;
    private DexEngine engine;

    DexEngineInitializer(
            final Config config,
            final DataSourceRegistry dataSourceRegistry) {
        this.config = config;
        this.dataSourceRegistry = dataSourceRegistry;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public DexEngineInitializer() {
        this(ConfigProvider.getConfig(), DataSourceRegistry.getInstance());
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        // NB: DexEngineConfigMapping is only available when engine is enabled,
        // so have to check enablement manually first.
        if (!config.getOptionalValue("dt.dex-engine.enabled", boolean.class).orElse(false)) {
            return;
        }

        final var configMapping = config
                .unwrap(SmallRyeConfig.class)
                .getConfigMapping(DexEngineConfigMapping.class);

        final DexEngineConfig engineConfig = createEngineConfig(configMapping);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Effective configuration: {}", engineConfig);
        }

        final var engineFactory = ServiceLoader.load(DexEngineFactory.class).findFirst().orElseThrow();
        engine = engineFactory.create(engineConfig);
        DexEngineHolder.set(engine);

        // TODO: Register workflows and activities here.

        ensureTaskQueues(
                engine,
                new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "default", 100),
                new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "default", 25));

        registerTaskWorkers(engine, configMapping);

        LOGGER.info("Starting dex engine");
        engine.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (engine == null) {
            return;
        }

        LOGGER.info("Stopping dex engine");
        try {
            engine.close();
        } catch (IOException e) {
            LOGGER.error("Failed to stop engine", e);
        }
    }

    private DexEngineConfig createEngineConfig(DexEngineConfigMapping configMapping) {
        final DataSource dataSource = dataSourceRegistry.get(configMapping.dataSource().name());

        final var engineConfig = new DexEngineConfig(UUID.randomUUID(), dataSource);

        engineConfig.workflowTaskScheduler().setEnabled(configMapping.workflowTaskScheduler().enabled());
        engineConfig.workflowTaskScheduler().setPollInterval(configMapping.workflowTaskScheduler().pollInterval());

        engineConfig.activityTaskScheduler().setEnabled(configMapping.activityTaskScheduler().enabled());
        engineConfig.activityTaskScheduler().setPollInterval(configMapping.activityTaskScheduler().pollInterval());

        engineConfig.retention().setWorkerEnabled(configMapping.retention().enabled());
        engineConfig.retention().setDuration(configMapping.retention().duration());

        engineConfig.taskEventBuffer().setFlushInterval(configMapping.taskEventBuffer().flushInterval());
        engineConfig.taskEventBuffer().setMaxBatchSize(configMapping.taskEventBuffer().maxSize());

        engineConfig.externalEventBuffer().setFlushInterval(configMapping.externalEventBuffer().flushInterval());
        engineConfig.externalEventBuffer().setMaxBatchSize(configMapping.externalEventBuffer().maxSize());

        engineConfig.activityTaskHeartbeatBuffer().setFlushInterval(configMapping.activityTaskHeartbeatBuffer().flushInterval());
        engineConfig.activityTaskHeartbeatBuffer().setMaxBatchSize(configMapping.activityTaskHeartbeatBuffer().maxSize());

        engineConfig.runHistoryCache().setEvictAfterAccess(configMapping.runHistoryCache().ttl());
        engineConfig.runHistoryCache().setMaxSize(configMapping.runHistoryCache().maxSize());

        engineConfig.setPageTokenEncoder(new EncryptedPageTokenEncoder());
        engineConfig.setMeterRegistry(Metrics.globalRegistry);

        return engineConfig;
    }

    private void ensureTaskQueues(DexEngine engine, CreateTaskQueueRequest... requests) {
        for (final CreateTaskQueueRequest request : requests) {
            final boolean created = engine.createTaskQueue(request);
            if (created) {
                LOGGER.info(
                        "Task queue '{}' of type {} created with max concurrency {}",
                        request.name(), request.type(), request.maxConcurrency());
            } else {
                LOGGER.debug("Task queue '{}' of type {} already exists", request.name(), request.type());
            }
        }
    }

    private void registerTaskWorkers(DexEngine engine, DexEngineConfigMapping configMapping) {
        for (final var entry : configMapping.workflowTaskWorker().entrySet()) {
            final String name = entry.getKey();
            final TaskWorkerConfigMapping config = entry.getValue();

            if (!config.enabled()) {
                LOGGER.debug("Not registering workflow task worker '{}' because it is disabled", name);
                continue;
            }

            LOGGER.info(
                    "Registering workflow task worker '{}' for queue '{}' with max concurrency {}",
                    name, config.queueName(), config.maxConcurrency());
            engine.registerWorkflowWorker(
                    new WorkflowTaskWorkerOptions(name, config.queueName(), config.maxConcurrency())
                            .withMinPollInterval(config.minPollInterval())
                            .withPollBackoffFunction(config.pollBackoff().asIntervalFunction()));
        }

        for (final var entry : configMapping.activityTaskWorker().entrySet()) {
            final String name = entry.getKey();
            final TaskWorkerConfigMapping config = entry.getValue();

            if (!config.enabled()) {
                LOGGER.debug("Not registering activity task worker '{}' because it is disabled", name);
                continue;
            }

            LOGGER.info(
                    "Registering activity task worker '{}' for queue '{}' with max concurrency {}",
                    name, config.queueName(), config.maxConcurrency());
            engine.registerActivityWorker(
                    new ActivityTaskWorkerOptions(name, config.queueName(), config.maxConcurrency())
                            .withMinPollInterval(config.minPollInterval())
                            .withPollBackoffFunction(config.pollBackoff().asIntervalFunction()));
        }
    }

}
