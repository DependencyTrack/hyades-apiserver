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

import java.time.Duration;
import java.util.Optional;

import static org.dependencytrack.workflow.serialization.Serdes.protobufSerde;
import static org.dependencytrack.workflow.serialization.Serdes.voidSerde;

public class ProcessBomUploadWorkflowRunner implements WorkflowRunner<ProcessBomUploadWorkflowArgs, Void> {

    @Override
    public Optional<Void> run(final WorkflowRunContext<ProcessBomUploadWorkflowArgs> ctx) throws Exception {
        final ProcessBomUploadWorkflowArgs workflowArgs = ctx.arguments().orElseThrow();

        try {
            final var activityArgs = IngestBomActivityArgs.newBuilder()
                    .setProject(workflowArgs.getProject())
                    .setBomFilePath(workflowArgs.getBomFilePath())
                    .build();
            ctx.callActivity("ingest-bom", "123",
                    activityArgs, protobufSerde(IngestBomActivityArgs.class), voidSerde(), Duration.ZERO);
        } catch (WorkflowActivityFailedException e) {
            throw new IllegalStateException("Failed to ingest BOM", e.getCause());
        }

        try {
            ctx.callActivity("scan-project-vulns", "456", null, voidSerde(), voidSerde(), Duration.ZERO);
        } catch (WorkflowActivityFailedException e) {
            throw new IllegalStateException("Failed to scan project for vulnerabilities", e.getCause());
        }

        // TODO: Wait for vulnerability scan to complete.

        try {
            final var activityArgs = EvaluateProjectPoliciesActivityArgs.newBuilder()
                    .setProject(workflowArgs.getProject())
                    .build();
            ctx.callActivity("evaluate-project-policies", "789",
                    activityArgs, protobufSerde(EvaluateProjectPoliciesActivityArgs.class), voidSerde(), Duration.ZERO);
        } catch (WorkflowActivityFailedException e) {
            throw new IllegalStateException("Failed to evaluate project policies", e.getCause());
        }

        try {
            final var activityArgs = UpdateProjectMetricsActivityArgs.newBuilder()
                    .setProject(workflowArgs.getProject())
                    .build();
            ctx.callActivity("update-project-metrics", "666", null, voidSerde(), voidSerde(), Duration.ZERO);
        } catch (WorkflowActivityFailedException e) {
            throw new IllegalStateException("Failed to update project metrics", e.getCause());
        }

        return Optional.empty();
    }

}
