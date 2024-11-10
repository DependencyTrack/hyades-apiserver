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

import alpine.common.logging.Logger;
import org.dependencytrack.exception.TransientException;
import org.dependencytrack.proto.workflow.payload.v1alpha1.EvaluateProjectPoliciesActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.IngestBomActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessBomUploadWorkflowArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsActivityArgs;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.workflow.model.ScheduleWorkflowOptions;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Optional;

import static org.dependencytrack.workflow.serialization.Serdes.protobufSerde;
import static org.dependencytrack.workflow.serialization.Serdes.voidSerde;

public class WorkflowSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(WorkflowSubsystemInitializer.class);

    private WorkflowEngine workflowEngine;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing workflow engine");
        workflowEngine = WorkflowEngine.getInstance();
        workflowEngine.start();

        final var random = new SecureRandom();

        workflowEngine.registerWorkflowRunner(
                new MirrorVulnSourcesWorkflowRunner(),
                /* concurrency */ 1,
                /* argumentsSerde */ voidSerde(),
                /* resultSerde */ voidSerde());

        workflowEngine.registerWorkflowRunner(
                new ProcessBomUploadWorkflowRunner(),
                /* concurrency */ 5,
                /* argumentsSerde */ protobufSerde(ProcessBomUploadWorkflowArgs.class),
                /* resultSerde */ voidSerde());

        workflowEngine.registerActivityRunner(
                new BomUploadProcessingTask(),
                /* concurrency */ 5,
                /* argumentsSerde */ protobufSerde(IngestBomActivityArgs.class),
                /* resultSerde */ voidSerde());
        workflowEngine.registerActivityRunner(
                "scan-project-vulns",
                /* concurrency */ 5,
                /* argumentsSerde */ voidSerde(),
                /* resultSerde */ voidSerde(),
                new RandomlyFailingActivityRunner(random));
        workflowEngine.registerActivityRunner(
                new PolicyEvaluationTask(),
                /* concurrency */ 5,
                /* argumentsSerde */ protobufSerde(EvaluateProjectPoliciesActivityArgs.class),
                /* resultSerde */ voidSerde());
        workflowEngine.registerActivityRunner(
                new ProjectMetricsUpdateTask(),
                /* concurrency */ 5,
                /* argumentsSerde */ protobufSerde(UpdateProjectMetricsActivityArgs.class),
                /* resultSerde */ voidSerde());

        workflowEngine.scheduleWorkflow(new ScheduleWorkflowOptions(
                "Vulnerability Sources Mirroring",
                "0 4 * * *",
                /* workflowName */ "mirror-vuln-sources",
                /* workflowVersion */ 1,
                /* priority */ null,
                MirrorVulnSourcesWorkflowRunner.UNIQUE_KEY,
                /* arguments */ null));
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down workflow engine");

        try {
            workflowEngine.close();
        } catch (IOException | RuntimeException e) {
            LOGGER.warn("Graceful shutdown of workflow engine failed", e);
        }
    }

    public static class RandomlyFailingActivityRunner implements WorkflowActivityRunner<Void, Void> {

        private static final Logger LOGGER = Logger.getLogger(RandomlyFailingActivityRunner.class);
        private final SecureRandom random;

        public RandomlyFailingActivityRunner(final SecureRandom random) {
            this.random = random;
        }

        @Override
        public Optional<Void> run(final WorkflowActivityContext<Void> ctx) throws Exception {
            LOGGER.debug("Processing " + ctx);

            Thread.sleep(random.nextInt(10, 1000));

            if (random.nextDouble() < 0.1) {
                if (random.nextDouble() > 0.3) {
                    throw new TransientException("I have the feeling this might resolve soon!");
                }

                throw new IllegalStateException("Oh no, this looks permanently broken!");
            }

            return Optional.empty();
        }

    }

}
