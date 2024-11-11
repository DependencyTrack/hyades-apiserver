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
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsActivityArgs;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.workflow.annotation.Workflow;

import java.time.Duration;
import java.util.Optional;

import static org.dependencytrack.workflow.payload.PayloadConverters.protobufConverter;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

@Workflow(name = "process-bom-upload")
public class ProcessBomUploadWorkflowRunner implements WorkflowRunner<ProcessBomUploadWorkflowArgs, Void> {

    @Override
    public Optional<Void> run(final WorkflowRunContext<ProcessBomUploadWorkflowArgs> ctx) throws Exception {
        final ProcessBomUploadWorkflowArgs workflowArgs = ctx.argument().orElseThrow();

        final var ingestBomArgs = IngestBomActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .setBomFilePath(workflowArgs.getBomFilePath())
                .build();
        ctx.callActivity(BomUploadProcessingTask.class, "123",
                ingestBomArgs, protobufConverter(IngestBomActivityArgs.class), voidConverter(), Duration.ZERO);

        /* final UUID vulnScanCompletionEventId = */
        ctx.callActivity("scan-project-vulns", "456", null, voidConverter(), voidConverter(), Duration.ZERO);

        // TODO: ctx.awaitExternalEvent(vulnScanCompletionEventId, voidConverter());

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

        Logger.getLogger(getClass()).info("Workflow completed");
        return Optional.empty();
    }

}
