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

import org.dependencytrack.proto.workflow.payload.v1alpha1.EvalProjectPoliciesArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.IngestBomArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessBomUploadArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.TriggerProjectVulnAnalysisArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.TriggerProjectVulnAnalysisResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsArgs;
import org.dependencytrack.workflow.annotation.Workflow;

import java.time.Duration;
import java.util.Optional;

import static org.dependencytrack.workflow.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.workflow.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

@Workflow(name = "process-bom-upload")
public class ProcessBomUploadWorkflowRunner implements WorkflowRunner<ProcessBomUploadArgs, Void> {

    private static final String STATUS_INGESTING_BOM = "INGESTING_BOM";
    private static final String STATUS_ANALYZING_VULNS = "ANALYZING_VULNS";
    private static final String STATUS_EVALUATING_POLICIES = "EVALUATING_POLICIES";
    private static final String STATUS_UPDATING_METRICS = "UPDATING_METRICS";
    private static final String STATUS_PROCESSED = "PROCESSED";

    @Override
    public Optional<Void> run(final WorkflowRunContext<ProcessBomUploadArgs, Void> ctx) throws Exception {
        final ProcessBomUploadArgs args = ctx.argument().orElseThrow();
        ctx.logger().info("Processing BOM upload");

        ctx.logger().info("Scheduling BOM ingestion");
        ctx.setStatus(STATUS_INGESTING_BOM);
        ctx.callActivity(
                "ingest-bom",
                IngestBomArgs.newBuilder()
                        .setProject(args.getProject())
                        .setBomFileMetadata(args.getBomFileMetadata())
                        .build(),
                protoConverter(IngestBomArgs.class),
                voidConverter(),
                defaultRetryPolicy()
                        .withMaxAttempts(6)).await();

        ctx.logger().info("Triggering vulnerability analysis");
        ctx.setStatus(STATUS_ANALYZING_VULNS);
        final Optional<TriggerProjectVulnAnalysisResult> vulnAnalysisResult =
                ctx.callActivity(
                        "trigger-project-vuln-analysis",
                        TriggerProjectVulnAnalysisArgs.newBuilder()
                                .setProject(args.getProject())
                                .build(),
                        protoConverter(TriggerProjectVulnAnalysisArgs.class),
                        protoConverter(TriggerProjectVulnAnalysisResult.class),
                        defaultRetryPolicy()
                                .withMaxAttempts(6)).await();

        if (vulnAnalysisResult.isPresent()) {
            ctx.logger().info("Waiting for vulnerability analysis to complete");
            ctx.waitForExternalEvent(
                    vulnAnalysisResult.get().getScanToken(),
                    voidConverter(),
                    Duration.ofMinutes(30)).await();
        } else {
            // NB: This can happen when the project is empty.
            // TODO: Return the reason in the activity result.
            ctx.logger().info("Vulnerability analysis was not triggered");
        }

        ctx.logger().info("Scheduling policy evaluation");
        ctx.setStatus(STATUS_EVALUATING_POLICIES);
        ctx.callActivity(
                "eval-project-policies",
                EvalProjectPoliciesArgs.newBuilder()
                        .setProject(args.getProject())
                        .build(),
                protoConverter(EvalProjectPoliciesArgs.class),
                voidConverter(),
                defaultRetryPolicy()
                        .withMaxAttempts(6)).await();

        ctx.logger().info("Scheduling metrics update");
        ctx.setStatus(STATUS_UPDATING_METRICS);
        ctx.callActivity(
                "update-project-metrics",
                UpdateProjectMetricsArgs.newBuilder()
                        .setProject(args.getProject())
                        .build(),
                protoConverter(UpdateProjectMetricsArgs.class),
                voidConverter(),
                defaultRetryPolicy()
                        .withMaxAttempts(6)).await();

        ctx.logger().info("BOM upload processed successfully");
        ctx.setStatus(STATUS_PROCESSED);
        return Optional.empty();
    }

}