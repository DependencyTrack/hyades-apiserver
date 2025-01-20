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

import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.IngestBomArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessBomUploadArgs;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.workflow.framework.WorkflowRunContext;
import org.dependencytrack.workflow.framework.WorkflowRunner;
import org.dependencytrack.workflow.framework.annotation.Workflow;

import java.util.Optional;

import static org.dependencytrack.workflow.framework.RetryPolicy.defaultRetryPolicy;

@Workflow(name = "process-bom-upload")
public class ProcessBomUploadWorkflow implements WorkflowRunner<ProcessBomUploadArgs, Void> {

    private static final String STATUS_INGESTING_BOM = "INGESTING_BOM";
    private static final String STATUS_ANALYZING = "ANALYZING";
    private static final String STATUS_PROCESSED = "PROCESSED";

    @Override
    public Optional<Void> run(final WorkflowRunContext<ProcessBomUploadArgs, Void> ctx) throws Exception {
        final ProcessBomUploadArgs args = ctx.argument().orElseThrow();
        ctx.logger().info("Processing BOM upload");

        ctx.logger().info("Scheduling BOM ingestion");
        ctx.setStatus(STATUS_INGESTING_BOM);
        BomUploadProcessingTask.ACTIVITY_CLIENT.call(
                ctx,
                IngestBomArgs.newBuilder()
                        .setProject(args.getProject())
                        .setBomFileMetadata(args.getBomFileMetadata())
                        .build(),
                defaultRetryPolicy()
                        .withMaxAttempts(6)).await();

        ctx.logger().info("Triggering project analysis");
        ctx.setStatus(STATUS_ANALYZING);
        AnalyzeProjectWorkflow.CLIENT.callWithConcurrencyGroupId(
                ctx,
                "analyze-project-" + args.getProject().getUuid(),
                AnalyzeProjectArgs.newBuilder()
                        .setProject(args.getProject())
                        .build()).await();

        ctx.logger().info("BOM upload processed successfully");
        ctx.setStatus(STATUS_PROCESSED);
        return Optional.empty();
    }

}
