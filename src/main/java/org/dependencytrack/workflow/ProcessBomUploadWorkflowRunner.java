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

import org.dependencytrack.proto.workflow.payload.v1alpha1.EvaluateProjectPoliciesActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.IngestBomActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessBomUploadWorkflowArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsActivityArgs;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.workflow.WorkflowSubsystemInitializer.RandomlyFailingActivityRunner;
import org.dependencytrack.workflow.annotation.Workflow;

import java.time.Duration;
import java.util.Optional;

import static org.dependencytrack.workflow.serialization.Serdes.protobufSerde;
import static org.dependencytrack.workflow.serialization.Serdes.voidSerde;

@Workflow(name = "process-bom-upload")
public class ProcessBomUploadWorkflowRunner implements WorkflowRunner<ProcessBomUploadWorkflowArgs, Void> {

    @Override
    public Optional<Void> run(final WorkflowRunContext<ProcessBomUploadWorkflowArgs> ctx) throws Exception {
        final ProcessBomUploadWorkflowArgs workflowArgs = ctx.arguments().orElseThrow();

        final var ingestBomArgs = IngestBomActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .setBomFilePath(workflowArgs.getBomFilePath())
                .build();
        ctx.callActivity(BomUploadProcessingTask.class, "123",
                ingestBomArgs, protobufSerde(IngestBomActivityArgs.class), voidSerde(), Duration.ZERO);

        /* final UUID vulnScanCompletionEventId = */
        ctx.callActivity(RandomlyFailingActivityRunner.class, "456", null, voidSerde(), voidSerde(), Duration.ZERO);

        // TODO: ctx.awaitExternalEvent(vulnScanCompletionEventId, voidSerde());

        final var evalPoliciesArgs = EvaluateProjectPoliciesActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .build();
        ctx.callActivity(PolicyEvaluationTask.class, "789",
                evalPoliciesArgs, protobufSerde(EvaluateProjectPoliciesActivityArgs.class), voidSerde(), Duration.ZERO);

        final var updateMetricsArgs = UpdateProjectMetricsActivityArgs.newBuilder()
                .setProject(workflowArgs.getProject())
                .build();
        ctx.callActivity(ProjectMetricsUpdateTask.class, "666",
                updateMetricsArgs, protobufSerde(UpdateProjectMetricsActivityArgs.class), voidSerde(), Duration.ZERO);

        return Optional.empty();
    }

}
