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
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.server.persistence.PersistenceManagerFactory;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResultX;
import org.dependencytrack.proto.workflow.payload.v1alpha1.EvalProjectPoliciesArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.IngestBomArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessBomUploadArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectAnalysisResultsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsArgs;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.framework.ActivityRunner;
import org.dependencytrack.workflow.framework.FaultInjectingActivityRunner;
import org.dependencytrack.workflow.framework.WorkflowEngine;
import org.dependencytrack.workflow.framework.WorkflowEngineConfig;
import org.dependencytrack.workflow.framework.persistence.Migration;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import javax.jdo.PersistenceManager;
import javax.sql.DataSource;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;

import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

public class WorkflowEngineInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngineInitializer.class);

    private static WorkflowEngine engine;

    public static WorkflowEngine workflowEngine() {
        return engine;
    }

    public void startWorkflowEngine() {
        if (engine != null
            && engine.state() != WorkflowEngine.State.CREATED
            && engine.state() != WorkflowEngine.State.STOPPED) {
            throw new IllegalStateException("Workflow engine is already started");
        }

        final DataSource dataSource = getEngineDataSource();
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.INIT_TASKS_ENABLED)) {
            try {
                Migration.run(dataSource);
            } catch (Throwable t) {
                LOGGER.error("Failed execute workflow engine database migrations", t);
                System.exit(1);
            }

            if (Config.getInstance().getPropertyAsBoolean(ConfigKey.INIT_AND_EXIT)) {
                LOGGER.info("Exiting because %s is enabled".formatted(ConfigKey.INIT_AND_EXIT.getPropertyName()));
                System.exit(0);
            }
        }

        final var config = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);

        final int externalEventBufferFlushIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_BUFFER_EXTERNAL_EVENT_FLUSH_INTERVAL_MS);
        final int externalEventBufferMaxBatchSize = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_BUFFER_EXTERNAL_EVENT_MAX_BATCH_SIZE);
        if (externalEventBufferFlushIntervalMillis >= 0) {
            config.externalEventBuffer().setFlushInterval(
                    Duration.ofMillis(externalEventBufferFlushIntervalMillis));
        }
        if (externalEventBufferMaxBatchSize > 0) {
            config.externalEventBuffer().setMaxBatchSize(externalEventBufferMaxBatchSize);
        }

        final int taskActionBufferFlushIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_BUFFER_TASK_ACTION_FLUSH_INTERVAL_MS);
        final int taskActionBufferMaxBatchSize = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_BUFFER_TASK_ACTION_MAX_BATCH_SIZE);
        if (taskActionBufferFlushIntervalMillis >= 0) {
            config.taskActionBuffer().setFlushInterval(
                    Duration.ofMillis(taskActionBufferFlushIntervalMillis));
        }
        if (taskActionBufferMaxBatchSize > 0) {
            config.taskActionBuffer().setMaxBatchSize(taskActionBufferMaxBatchSize);
        }

        final int workflowTaskDispatcherMinPollIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS);
        final int activityTaskDispatcherMinPollIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_ACTIVITY_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS);
        if (workflowTaskDispatcherMinPollIntervalMillis >= 0) {
            config.workflowTaskDispatcher().setMinPollInterval(Duration.ofMillis(workflowTaskDispatcherMinPollIntervalMillis));
        }
        if (activityTaskDispatcherMinPollIntervalMillis >= 0) {
            config.activityTaskDispatcher().setMinPollInterval(Duration.ofMillis(activityTaskDispatcherMinPollIntervalMillis));
        }

        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            config.setMeterRegistry(Metrics.getRegistry());
        }

        engine = new WorkflowEngine(config);
        engine.start();

        // TODO: Make configurable which runners are registered,
        //  their max concurrency, and their lock timeout.

        engine.registerWorkflowRunner(
                new ProcessBomUploadWorkflow(),
                /* maxConcurrency */ 50,
                /* argumentConverter */ protoConverter(ProcessBomUploadArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerWorkflowRunner(
                new AnalyzeProjectWorkflow(),
                /* maxConcurrency */ 50,
                /* argumentConverter */ protoConverter(AnalyzeProjectArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));

        final var random = new SecureRandom();

        engine.registerActivityRunner(
                maybeFaultInjecting(new BomUploadProcessingTask(), random),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(IngestBomArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                maybeFaultInjecting(new InternalVulnerabilityAnalysisActivity(), random),
                /* maxConcurrency */ 20,
                /* argumentConverter */ protoConverter(AnalyzeProjectArgs.class),
                /* resultConverter */ protoConverter(AnalyzeProjectVulnsResultX.class),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                maybeFaultInjecting(new OssIndexVulnerabilityAnalysisActivity(), random),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(AnalyzeProjectArgs.class),
                /* resultConverter */ protoConverter(AnalyzeProjectVulnsResultX.class),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                maybeFaultInjecting(new ProcessProjectAnalysisResultsActivity(), random),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(ProcessProjectAnalysisResultsArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                maybeFaultInjecting(new PolicyEvaluationTask(), random),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(EvalProjectPoliciesArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                maybeFaultInjecting(new ProjectMetricsUpdateTask(), random),
                /* maxConcurrency */ 20,
                /* argumentConverter */ protoConverter(UpdateProjectMetricsArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
    }

    public static void stopWorkflowEngine() {
        if (engine == null) {
            return;
        }

        try {
            engine.close();
        } catch (Exception e) {
            LOGGER.warn("Failed to stop workflow engine", e);
        }
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_ENABLED)) {
            return;
        }

        LOGGER.info("Starting workflow engine");
        startWorkflowEngine();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Stopping workflow engine");
        stopWorkflowEngine();
    }

    private static DataSource getEngineDataSource() {
        final String dedicatedDatabaseUrl = Config.getInstance().getProperty(
                ConfigKey.WORKFLOW_ENGINE_DATABASE_URL);
        if (dedicatedDatabaseUrl != null) {
            final var hikariConfig = new HikariConfig();
            hikariConfig.setDriverClassName(org.postgresql.Driver.class.getName());
            hikariConfig.setJdbcUrl(dedicatedDatabaseUrl);
            hikariConfig.setUsername(Config.getInstance().getProperty(ConfigKey.WORKFLOW_ENGINE_DATABASE_USERNAME));
            hikariConfig.setPassword(Config.getInstance().getProperty(ConfigKey.WORKFLOW_ENGINE_DATABASE_PASSWORD));
            // TODO: Some more pool properties?

            // TODO: Use pool properties specific to workflow engine.
            hikariConfig.setMaximumPoolSize(Config.getInstance().getPropertyAsInt(Config.AlpineKey.DATABASE_POOL_MAX_SIZE));
            hikariConfig.setMinimumIdle(Config.getInstance().getPropertyAsInt(Config.AlpineKey.DATABASE_POOL_MIN_IDLE));
            return new HikariDataSource(hikariConfig);
        }

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            return PersistenceUtil.getDataSource(pm);
        }
    }

    private static <A, R> ActivityRunner<A, R> maybeFaultInjecting(
            final ActivityRunner<A, R> activityRunner,
            final SecureRandom random) {
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_INJECT_ACTIVITY_FAULTS)) {
            return new FaultInjectingActivityRunner<>(activityRunner, random);
        }

        return activityRunner;
    }

}
