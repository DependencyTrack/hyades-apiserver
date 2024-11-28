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
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.EvalProjectPoliciesArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.IngestBomArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessBomUploadArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsArgs;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.VulnerabilityAnalysisTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;

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
                /* maxConcurrency */ 5,
                /* argumentConverter */ protoConverter(ProcessBomUploadArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));

        engine.registerActivityRunner(
                new BomUploadProcessingTask(),
                /* maxConcurrency */ 5,
                /* argumentConverter */ protoConverter(IngestBomArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                new VulnerabilityAnalysisTask(),
                /* maxConcurrency */ 5,
                /* argumentConverter */ protoConverter(AnalyzeProjectVulnsArgs.class),
                /* resultConverter */ protoConverter(AnalyzeProjectVulnsResult.class),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                new PolicyEvaluationTask(),
                /* maxConcurrency */ 5,
                /* argumentConverter */ protoConverter(EvalProjectPoliciesArgs.class),
                /* resultConverter */ voidConverter(),
                /* lockTimeout */ Duration.ofSeconds(30));
        engine.registerActivityRunner(
                new ProjectMetricsUpdateTask(),
                /* maxConcurrency */ 5,
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

    public static class RandomlyFailingActivityRunner implements ActivityRunner<Void, Void> {

        private static final Logger LOGGER = Logger.getLogger(RandomlyFailingActivityRunner.class);
        private final SecureRandom random;

        public RandomlyFailingActivityRunner(final SecureRandom random) {
            this.random = random;
        }

        @Override
        public Optional<Void> run(final ActivityRunContext<Void> ctx) throws Exception {
            LOGGER.debug("Processing " + ctx);

            Thread.sleep(random.nextInt(10, 1000));

            if (random.nextDouble() < 0.1) {
                throw new IllegalStateException("Oh no, this looks permanently broken!");
            }

            return Optional.empty();
        }

    }

}
