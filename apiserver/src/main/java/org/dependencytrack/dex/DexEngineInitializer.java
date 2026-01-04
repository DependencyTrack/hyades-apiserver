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

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Metrics;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.EncryptedPageTokenEncoder;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.dependencytrack.config.templating.ConfigTemplateRenderer;
import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.activity.PublishNotificationActivity;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.DexEngineFactory;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.workflow.PublishNotificationWorkflow;
import org.dependencytrack.dex.workflow.proto.v1.DeleteFilesArgument;
import org.dependencytrack.dex.workflow.proto.v1.PublishNotificationArgument;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.secret.management.SecretManager;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

/**
 * @since 5.7.0
 */
public final class DexEngineInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(DexEngineInitializer.class);

    private final Config config;
    private final DataSourceRegistry dataSourceRegistry;
    private @Nullable DexEngine engine;

    DexEngineInitializer(Config config, DataSourceRegistry dataSourceRegistry) {
        this.config = config;
        this.dataSourceRegistry = dataSourceRegistry;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public DexEngineInitializer() {
        this(ConfigProvider.getConfig(), DataSourceRegistry.getInstance());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        final DexEngineConfig engineConfig = createEngineConfig();
        LOGGER.debug("Effective configuration: {}", engineConfig);

        final ServletContext servletContext = event.getServletContext();

        final var healthCheckRegistry = (HealthCheckRegistry) servletContext.getAttribute(HealthCheckRegistry.class.getName());
        requireNonNull(healthCheckRegistry, "healthCheckRegistry has not been initialized");

        final var pluginManager = (PluginManager) servletContext.getAttribute(PluginManager.class.getName());
        requireNonNull(pluginManager, "pluginManager has not been initialized");

        final var secretManager = (SecretManager) servletContext.getAttribute(SecretManager.class.getName());
        requireNonNull(pluginManager, "secretManager has not been initialized");

        final var engineFactory = ServiceLoader.load(DexEngineFactory.class).findFirst().orElseThrow();
        engine = engineFactory.create(engineConfig);

        engine.registerWorkflow(
                new PublishNotificationWorkflow(),
                protoConverter(PublishNotificationArgument.class),
                voidConverter(),
                Duration.ofMinutes(1));
        engine.registerActivity(
                new DeleteFilesActivity(pluginManager),
                protoConverter(DeleteFilesArgument.class),
                voidConverter(),
                Duration.ofMinutes(1));
        engine.registerActivity(
                new PublishNotificationActivity(
                        pluginManager,
                        new ConfigTemplateRenderer(secretManager::getSecretValue),
                        new PebbleNotificationTemplateRendererFactory(Collections.emptyMap())),
                protoConverter(PublishNotificationArgument.class),
                voidConverter(),
                Duration.ofMinutes(1));

        ensureTaskQueues(engine, List.of(
                new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1000),
                new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1000),
                new CreateTaskQueueRequest(TaskType.ACTIVITY, "notification", 5)));

        final List<String> taskWorkerNames = getTaskWorkerNames(config);
        for (final var workerName : taskWorkerNames) {
            LOGGER.info("Registering task worker {}", workerName);

            final TaskWorkerOptions workerOptions = getTaskWorkerOptions(config, workerName);
            engine.registerTaskWorker(workerOptions);
        }

        LOGGER.info("Starting durable execution engine");
        healthCheckRegistry.addCheck(new DexEngineHealthCheck(engine));
        engine.start();

        servletContext.setAttribute(DexEngine.class.getName(), engine);
    }

    @Override
    public void contextDestroyed(@Nullable ServletContextEvent ignored) {
        if (engine == null) {
            return;
        }

        LOGGER.info("Stopping durable execution engine");
        try {
            engine.close();
        } catch (IOException e) {
            LOGGER.error("Failed to stop durable execution engine", e);
        }
    }

    private DexEngineConfig createEngineConfig() {
        final String dataSourceName = config.getValue("dt.dex-engine.datasource.name", String.class);
        final DataSource dataSource = dataSourceRegistry.get(dataSourceName);

        final var engineConfig = new DexEngineConfig(dataSource);
        engineConfig.setMeterRegistry(Metrics.globalRegistry);
        engineConfig.setPageTokenEncoder(new EncryptedPageTokenEncoder());

        // Leader election.
        config.getOptionalValue("dt.dex-engine.leader-election.lease-duration-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.leaderElection()::setLeaseDuration);
        config.getOptionalValue("dt.dex-engine.leader-election.lease-check-interval-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.leaderElection()::setLeaseCheckInterval);

        // Workflow task scheduler.
        config.getOptionalValue("dt.dex-engine.workflow-task-scheduler.poll-interval-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.workflowTaskScheduler()::setPollInterval);
        getBackoffFunction(config, "dt.dex-engine.workflow-task-scheduler.poll-backoff")
                .ifPresent(engineConfig.workflowTaskScheduler()::setPollBackoffFunction);

        // Activity task scheduler.
        config.getOptionalValue("dt.dex-engine.activity-task-scheduler.poll-interval-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.activityTaskScheduler()::setPollInterval);
        getBackoffFunction(config, "dt.dex-engine.activity-task-scheduler.poll-backoff")
                .ifPresent(engineConfig.activityTaskScheduler()::setPollBackoffFunction);

        // Task event buffer.
        config.getOptionalValue("dt.dex-engine.task-event-buffer.flush-interval-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.taskEventBuffer()::setFlushInterval);
        config.getOptionalValue("dt.dex-engine.task-event-buffer.max-batch-size", int.class)
                .ifPresent(engineConfig.taskEventBuffer()::setMaxBatchSize);

        // External event buffer.
        config.getOptionalValue("dt.dex-engine.external-event-buffer.flush-interval-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.externalEventBuffer()::setFlushInterval);
        config.getOptionalValue("dt.dex-engine.external-event-buffer.max-batch-size", int.class)
                .ifPresent(engineConfig.externalEventBuffer()::setMaxBatchSize);

        // Activity task heartbeat buffer.
        config.getOptionalValue("dt.dex-engine.activity-task-heartbeat-buffer.flush-interval-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.activityTaskHeartbeatBuffer()::setFlushInterval);
        config.getOptionalValue("dt.dex-engine.activity-task-heartbeat-buffer.max-batch-size", int.class)
                .ifPresent(engineConfig.activityTaskHeartbeatBuffer()::setMaxBatchSize);

        // Run history cache.
        config.getOptionalValue("dt.dex-engine.run-history-cache.evict-after-access-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.runHistoryCache()::setEvictAfterAccess);
        config.getOptionalValue("dt.dex-engine.run-history-cache.max-size", int.class)
                .ifPresent(engineConfig.runHistoryCache()::setMaxSize);

        // Maintenance.
        config.getOptionalValue("dt.dex-engine.maintenance.worker.initial-delay-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.maintenance()::setWorkerInitialDelay);
        config.getOptionalValue("dt.dex-engine.maintenance.worker.interval-ms", long.class)
                .map(Duration::ofMillis)
                .ifPresent(engineConfig.maintenance()::setWorkerInterval);
        config.getOptionalValue("dt.dex-engine.maintenance.run-retention-duration", Duration.class)
                .ifPresent(engineConfig.maintenance()::setRunRetentionDuration);
        config.getOptionalValue("dt.dex-engine.maintenance.run-deletion-batch-size", int.class)
                .ifPresent(engineConfig.maintenance()::setRunDeletionBatchSize);

        return engineConfig;
    }

    private void ensureTaskQueues(DexEngine engine, Collection<CreateTaskQueueRequest> requests) {
        for (final var request : requests) {
            final boolean created = engine.createTaskQueue(request);
            if (created) {
                LOGGER.info(
                        "Created {} task queue '{}' with capacity {}",
                        request.type().name().toLowerCase(),
                        request.name(),
                        request.capacity());
            }
        }
    }

    private static final Pattern TASK_WORKER_PROPERTY_PATTERN =
            Pattern.compile("^dt\\.dex-engine\\.task-worker\\..+\\..+$");

    private static List<String> getTaskWorkerNames(Config config) {
        return StreamSupport.stream(config.getPropertyNames().spliterator(), false)
                .filter(name -> TASK_WORKER_PROPERTY_PATTERN.matcher(name).matches())
                .map(name -> name.split("\\.", 5)[3])
                .distinct()
                .toList();
    }

    private static TaskWorkerOptions getTaskWorkerOptions(Config config, String name) {
        final var prefix = "dt.dex-engine.task-worker.%s.".formatted(name);

        final var type = config.getValue(prefix + "type", TaskType.class);
        final var queueName = config.getValue(prefix + "queue-name", String.class);
        final var maxConcurrency = config.getValue(prefix + "max-concurrency", int.class);
        final var minPollInterval = config
                .getOptionalValue(prefix + "min-poll-interval-ms", long.class)
                .map(Duration::ofMillis)
                .orElse(null);
        final IntervalFunction pollBackoffFunction = getBackoffFunction(config, prefix).orElse(null);

        var options = new TaskWorkerOptions(type, name, queueName, maxConcurrency);
        if (minPollInterval != null) {
            options = options.withMinPollInterval(minPollInterval);
        }
        if (pollBackoffFunction != null) {
            options = options.withPollBackoffFunction(pollBackoffFunction);
        }

        return options;
    }

    private static Optional<IntervalFunction> getBackoffFunction(Config config, String prefix) {
        final Optional<Long> initialDelayMillis = config.getOptionalValue(prefix + ".initial-delay-ms", long.class);
        final Optional<Double> multiplier = config.getOptionalValue(prefix + ".multiplier", double.class);
        final Optional<Double> randomizationFactor = config.getOptionalValue(prefix + ".randomization-factor", double.class);
        final Optional<Long> maxDelayMillis = config.getOptionalValue(prefix + ".max-delay-ms", long.class);

        if (initialDelayMillis.isEmpty()
                || multiplier.isEmpty()
                || randomizationFactor.isEmpty()
                || maxDelayMillis.isEmpty()) {
            return Optional.empty();
        }

        final var backoffFunction = IntervalFunction.ofExponentialRandomBackoff(
                initialDelayMillis.get(),
                multiplier.get(),
                randomizationFactor.get(),
                maxDelayMillis.get());

        return Optional.of(backoffFunction);
    }

}
