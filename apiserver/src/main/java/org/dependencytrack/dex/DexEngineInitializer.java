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
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.DexEngineFactory;
import org.dependencytrack.dex.engine.api.request.CreateActivityTaskQueueRequest;
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
        if (!config.getOptionalValue("dt.dex-engine.enabled", Boolean.class).orElse(false)) {
            return;
        }

        final DexEngineConfig engineConfig = createEngineConfig();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Effective configuration: {}", engineConfig);
        }

        final var engineFactory = ServiceLoader.load(DexEngineFactory.class).findFirst().orElseThrow();
        engine = engineFactory.create(engineConfig);
        DexEngineHolder.set(engine);

        // TODO: Register workflows and activities here.

        engine.createActivityTaskQueue(new CreateActivityTaskQueueRequest("default", 25));

        // TODO: Register workers based on configuration.

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

    private DexEngineConfig createEngineConfig() {
        final String dataSourceName = config.getValue("dt.dex-engine.datasource.name", String.class);
        final DataSource dataSource = dataSourceRegistry.get(dataSourceName);

        final var engineConfig = new DexEngineConfig(UUID.randomUUID(), dataSource);

        config.getOptionalValue("dt.dex-engine.cache.run-history.max-size", int.class)
                .ifPresent(engineConfig.runHistoryCache()::setMaxSize);
        config.getOptionalValue("dt.dex-engine.cache.run-history.ttl", Duration.class)
                .ifPresent(engineConfig.runHistoryCache()::setEvictAfterAccess);

        config.getOptionalValue("dt.dex-engine.buffer.external-event.flush-interval", Duration.class)
                .ifPresent(engineConfig.externalEventBuffer()::setFlushInterval);
        config.getOptionalValue("dt.dex-engine.buffer.external-event.max-size", int.class)
                .ifPresent(engineConfig.externalEventBuffer()::setMaxBatchSize);

        config.getOptionalValue("dt.dex-engine.buffer.task-command.flush-interval", Duration.class)
                .ifPresent(engineConfig.taskCommandBuffer()::setFlushInterval);
        config.getOptionalValue("dt.dex-engine.buffer.task-command.max-size", int.class)
                .ifPresent(engineConfig.taskCommandBuffer()::setMaxBatchSize);

        config.getOptionalValue("dt.dex-engine.retention.enabled", boolean.class)
                .ifPresent(engineConfig.retention()::setWorkerEnabled);
        config.getOptionalValue("dt.dex-engine.retention.days", int.class)
                .ifPresent(engineConfig.retention()::setDays);

        config.getOptionalValue("dt.dex-engine.task-worker.activity.min-poll-interval", Duration.class)
                .ifPresent(engineConfig.activityTaskWorker()::setMinPollInterval);
        engineConfig.activityTaskWorker().setPollBackoffIntervalFunction(ofExponentialRandomBackoff(
                config.getOptionalValue("dt.dex-engine.task-worker.activity.poll-backoff.initial-delay", Duration.class).orElseGet(() -> Duration.ofMillis(100)),
                config.getOptionalValue("dt.dex-engine.task-worker.activity.poll-backoff.multiplier", double.class).orElse(1.5),
                config.getOptionalValue("dt.dex-engine.task-worker.activity.poll-backoff.randomization-factor", double.class).orElse(0.3),
                config.getOptionalValue("dt.dex-engine.task-worker.activity.poll-backoff.max-delay", Duration.class).orElseGet(() -> Duration.ofSeconds(3))));

        config.getOptionalValue("dt.dex-engine.task-worker.workflow.min-poll-interval", Duration.class)
                .ifPresent(engineConfig.workflowTaskWorker()::setMinPollInterval);
        engineConfig.workflowTaskWorker().setPollBackoffIntervalFunction(ofExponentialRandomBackoff(
                config.getOptionalValue("dt.dex-engine.task-worker.workflow.poll-backoff.initial-delay", Duration.class).orElseGet(() -> Duration.ofMillis(100)),
                config.getOptionalValue("dt.dex-engine.task-worker.workflow.poll-backoff.multiplier", double.class).orElse(1.5),
                config.getOptionalValue("dt.dex-engine.task-worker.workflow.poll-backoff.randomization-factor", double.class).orElse(0.3),
                config.getOptionalValue("dt.dex-engine.task-worker.workflow.poll-backoff.max-delay", Duration.class).orElseGet(() -> Duration.ofSeconds(3))));

        if (config.getOptionalValue("alpine.metrics.enabled", boolean.class).orElse(false)) {
            engineConfig.setMeterRegistry(Metrics.globalRegistry);
        }

        return engineConfig;
    }

}
