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
import org.dependencytrack.proto.workflow.payload.v1alpha1.EvaluateProjectPoliciesActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.IngestBomActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessBomUploadWorkflowArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProjectVulnScanCompletedExternalEvent;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ScanProjectVulnsActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsActivityArgs;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.VulnerabilityAnalysisTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.workflow.annotation.Workflow;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import static org.dependencytrack.workflow.payload.PayloadConverters.protobufConverter;
import static org.dependencytrack.workflow.payload.PayloadConverters.uuidConverter;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

@Workflow(name = "process-bom-upload")
public class ProcessBomUploadWorkflowRunner implements WorkflowRunner<ProcessBomUploadWorkflowArgs, Void> {

    private static final Logger LOGGER = Logger.getLogger(ProcessBomUploadWorkflowRunner.class);

    @Override
    public Optional<Void> run(final WorkflowRunContext<ProcessBomUploadWorkflowArgs> ctx) throws Exception {
        final ProcessBomUploadWorkflowArgs workflowArgs = ctx.argument().orElseThrow();

        final var ingestBomArgs = IngestBomActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .setBomFilePath(workflowArgs.getBomFilePath())
                .build();
        ctx.callActivity(BomUploadProcessingTask.class, "123",
                ingestBomArgs, protobufConverter(IngestBomActivityArgs.class), voidConverter(), Duration.ZERO);

        final var scanVulnsArgs = ScanProjectVulnsActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .build();
        final Optional<UUID> vulnScanToken = ctx.callActivity(VulnerabilityAnalysisTask.class, "456",
                scanVulnsArgs, protobufConverter(ScanProjectVulnsActivityArgs.class), uuidConverter(), Duration.ZERO);

        // TODO: Read scan outcome from event.
        final var vulnScanCompletedEvent = vulnScanToken.flatMap(uuid -> ctx.awaitExternalEvent(
                uuid, protobufConverter(ProjectVulnScanCompletedExternalEvent.class)));
        LOGGER.info("Vulnerability scan " + vulnScanCompletedEvent.orElseThrow().getStatus());

        final var evalPoliciesArgs = EvaluateProjectPoliciesActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .build();
        ctx.callActivity(PolicyEvaluationTask.class, "789",
                evalPoliciesArgs, protobufConverter(EvaluateProjectPoliciesActivityArgs.class), voidConverter(), Duration.ZERO);

        final var updateMetricsArgs = UpdateProjectMetricsActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .build();
        ctx.callActivity(ProjectMetricsUpdateTask.class, "666",
                updateMetricsArgs, protobufConverter(UpdateProjectMetricsActivityArgs.class), voidConverter(), Duration.ZERO);

        return Optional.empty();
    }

}
