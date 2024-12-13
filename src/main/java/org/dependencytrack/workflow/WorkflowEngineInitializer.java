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

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.time.Duration;

import static org.dependencytrack.workflow.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

public class WorkflowEngineInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngineInitializer.class);

    private WorkflowEngine engine;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_ENABLED)) {
            return;
        }

        LOGGER.info("Starting workflow engine");

        engine = WorkflowEngine.getInstance();
        engine.start();

        engine.registerWorkflowRunner(
                new ProcessBomUploadWorkflowRunner(),
                /* maxConcurrency */ 25,
                /* argumentConverter */ protoConverter(ProcessBomUploadArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerWorkflowRunner(
                new AnalyzeProjectWorkflowRunner(),
                /* maxConcurrency */ 25,
                /* argumentConverter */ protoConverter(AnalyzeProjectArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));

        engine.registerActivityRunner(
                new BomUploadProcessingTask(),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(IngestBomArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                new OssIndexAnalysisActivity(),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(AnalyzeProjectArgs.class),
                /* resultConverter */ protoConverter(AnalyzeProjectVulnsResultX.class),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                new ProcessProjectAnalysisResultsActivity(),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(ProcessProjectAnalysisResultsArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                new PolicyEvaluationTask(),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(EvalProjectPoliciesArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                new ProjectMetricsUpdateTask(),
                /* maxConcurrency */ 10,
                /* argumentConverter */ protoConverter(UpdateProjectMetricsArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (engine == null) {
            return;
        }

        LOGGER.info("Stopping workflow engine");
        try {
            engine.close();
        } catch (Exception e) {
            LOGGER.warn("Failed to stop workflow engine", e);
        }
    }

}
