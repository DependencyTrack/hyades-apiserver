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
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.ActivityGroup;
import org.dependencytrack.workflow.framework.FaultInjectingActivityExecutor;
import org.dependencytrack.workflow.framework.WorkflowEngine;
import org.dependencytrack.workflow.framework.WorkflowEngineConfig;
import org.dependencytrack.workflow.framework.WorkflowGroup;
import org.dependencytrack.workflow.framework.persistence.Migration;
import org.dependencytrack.workflow.payload.proto.v1alpha1.AnalyzeProjectArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.AnalyzeProjectVulnsArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.workflow.payload.proto.v1alpha1.CloneProjectArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.CloneProjectResult;
import org.dependencytrack.workflow.payload.proto.v1alpha1.EvalProjectPoliciesArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.IngestBomArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.ProcessBomUploadArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.ProcessProjectVulnAnalysisResultsArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.PublishNotificationActivityArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.PublishNotificationWorkflowArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.UpdateProjectMetricsArgs;

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

        final int schedulerInitialDelayMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_SCHEDULER_INITIAL_DELAY_MS);
        final int schedulerPollIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_SCHEDULER_POLL_INTERVAL_MS);
        if (schedulerInitialDelayMillis >= 0) {
            config.scheduler().setInitialDelay(Duration.ofMillis(schedulerInitialDelayMillis));
        }
        if (schedulerPollIntervalMillis >= 0) {
            config.scheduler().setPollInterval(Duration.ofMillis(schedulerPollIntervalMillis));
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

        final int workflowRunTaskDispatcherMinPollIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS);
        final int activityTaskDispatcherMinPollIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_ACTIVITY_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS);
        if (workflowRunTaskDispatcherMinPollIntervalMillis >= 0) {
            config.workflowTaskDispatcher().setMinPollInterval(Duration.ofMillis(workflowRunTaskDispatcherMinPollIntervalMillis));
        }
        if (activityTaskDispatcherMinPollIntervalMillis >= 0) {
            config.activityTaskDispatcher().setMinPollInterval(Duration.ofMillis(activityTaskDispatcherMinPollIntervalMillis));
        }

        final int workflowRetentionDays = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_RETENTION_DAYS);
        final int workflowRetentionDeletionBatchSize = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_RETENTION_DELETION_BATCH_SIZE);
        final int workflowRetentionWorkerInitialDelayMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_RETENTION_WORKER_INITIAL_DELAY_MS);
        final int workflowRetentionWorkerIntervalMillis = Config.getInstance().getPropertyAsInt(
                ConfigKey.WORKFLOW_ENGINE_RETENTION_WORKER_INTERVAL_MS);
        if (workflowRetentionDays > 0) {
            config.retention().setDuration(Duration.ofDays(workflowRetentionDays));
        }
        if (workflowRetentionDeletionBatchSize > 0) {
            config.retention().setDeletionBatchSize(workflowRetentionDeletionBatchSize);
        }
        if (workflowRetentionWorkerInitialDelayMillis > 0) {
            config.retention().setWorkerInitialDelay(Duration.ofMillis(workflowRetentionWorkerInitialDelayMillis));
        }
        if (workflowRetentionWorkerIntervalMillis > 0) {
            config.retention().setWorkerInterval(Duration.ofMillis(workflowRetentionWorkerIntervalMillis));
        }

        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            config.setMeterRegistry(Metrics.getRegistry());
        }

        engine = new WorkflowEngine(config);

        engine.register(
                new ProcessBomUploadWorkflow(),
                protoConverter(ProcessBomUploadArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.register(
                new AnalyzeProjectWorkflow(),
                protoConverter(AnalyzeProjectArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.register(
                new CloneProjectWorkflow(),
                protoConverter(CloneProjectArgs.class),
                protoConverter(CloneProjectResult.class),
                Duration.ofSeconds(30));
        engine.register(
                new PublishNotificationWorkflow(),
                protoConverter(PublishNotificationWorkflowArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));

        final var random = new SecureRandom();

        engine.register(
                maybeFaultInjecting(new BomUploadProcessingTask(), random),
                protoConverter(IngestBomArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.register(
                maybeFaultInjecting(new AnalyzeProjectVulnsActivity(), random),
                protoConverter(AnalyzeProjectVulnsArgs.class),
                protoConverter(AnalyzeProjectVulnsResult.class),
                Duration.ofSeconds(30));
        engine.register(
                maybeFaultInjecting(new ProcessProjectVulnAnalysisResultsActivity(), random),
                protoConverter(ProcessProjectVulnAnalysisResultsArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.register(
                maybeFaultInjecting(new PolicyEvaluationTask(), random),
                protoConverter(EvalProjectPoliciesArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.register(
                maybeFaultInjecting(new ProjectMetricsUpdateTask(), random),
                protoConverter(UpdateProjectMetricsArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.register(
                maybeFaultInjecting(new CloneProjectActivity(), random),
                protoConverter(CloneProjectArgs.class),
                protoConverter(CloneProjectResult.class),
                Duration.ofSeconds(30));
        engine.register(
                maybeFaultInjecting(new PublishNotificationActivity(), random),
                protoConverter(PublishNotificationActivityArgs.class),
                voidConverter(),
                Duration.ofSeconds(30));

        engine.start();

        // TODO: Make configurable which runners are registered,
        //  their max concurrency, and their lock timeout.

        engine.mount(new ActivityGroup("bom")
                .withActivity(BomUploadProcessingTask.class)
                .withMaxConcurrency(10));
        engine.mount(new ActivityGroup("analysis")
                .withActivity(AnalyzeProjectVulnsActivity.class)
                .withActivity(ProcessProjectVulnAnalysisResultsActivity.class)
                .withActivity(PolicyEvaluationTask.class)
                .withMaxConcurrency(30));
        engine.mount(new ActivityGroup("metrics")
                .withActivity(ProjectMetricsUpdateTask.class)
                .withMaxConcurrency(10));
        engine.mount(new ActivityGroup("misc")
                .withActivity(CloneProjectActivity.class)
                .withMaxConcurrency(5));
        engine.mount(new ActivityGroup("notification")
                .withActivity(PublishNotificationActivity.class)
                .withMaxConcurrency(10));

        engine.mount(new WorkflowGroup("all")
                .withWorkflow(ProcessBomUploadWorkflow.class)
                .withWorkflow(AnalyzeProjectWorkflow.class)
                .withWorkflow(PublishNotificationWorkflow.class)
                .withWorkflow(CloneProjectWorkflow.class)
                .withMaxConcurrency(50));
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

    private static <A, R> ActivityExecutor<A, R> maybeFaultInjecting(
            final ActivityExecutor<A, R> activityExecutor,
            final SecureRandom random) {
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_INJECT_ACTIVITY_FAULTS)) {
            return new FaultInjectingActivityExecutor<>(activityExecutor, random);
        }

        return activityExecutor;
    }

}
