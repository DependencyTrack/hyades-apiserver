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

import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResultX;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzerStatuses;
import org.dependencytrack.proto.workflow.payload.v1alpha1.EvalProjectPoliciesArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectAnalysisResultsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsArgs;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.workflow.annotation.Workflow;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.workflow.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

@Workflow(name = "analyze-project")
public class AnalyzeProjectWorkflow implements WorkflowRunner<AnalyzeProjectArgs, Void> {

    private static final String STATUS_ANALYZING_VULNS = "ANALYZING_VULNS";
    private static final String STATUS_PROCESSING_VULN_ANALYSIS_RESULTS = "PROCESSING_VULN_ANALYSIS_RESULTS";
    private static final String STATUS_EVALUATING_POLICIES = "EVALUATING_POLICIES";
    private static final String STATUS_UPDATING_METRICS = "UPDATING_METRICS";
    private static final String STATUS_COMPLETED = "COMPLETED";

    @Override
    public Optional<Void> run(final WorkflowRunContext<AnalyzeProjectArgs, Void> ctx) throws Exception {
        final AnalyzeProjectArgs args = ctx.argument().orElseThrow();

        ctx.setStatus(STATUS_ANALYZING_VULNS);

        // Using side effect here because it's not worth scheduling
        // an asynchronous activity for this.
        final AnalyzerStatuses analyzerStatuses = ctx.sideEffect(
                "analyzer-statuses",
                /* argument */ null,
                protoConverter(AnalyzerStatuses.class),
                ignored -> getAnalyzerStatuses()).await().orElseThrow();

        final RetryPolicy scannerRetryPolicy = defaultRetryPolicy().withMaxAttempts(6);
        final var pendingScannerResults = new ArrayList<Awaitable<AnalyzeProjectVulnsResultX>>();
        if (analyzerStatuses.getInternalEnabled()) {
            ctx.logger().info("Scheduling internal analysis");
            pendingScannerResults.add(
                    ctx.callActivity(
                            InternalAnalysisActivity.class,
                            args,
                            protoConverter(AnalyzeProjectArgs.class),
                            protoConverter(AnalyzeProjectVulnsResultX.class),
                            scannerRetryPolicy));
        }
        if (analyzerStatuses.getOssIndexEnabled()) {
            ctx.logger().info("Scheduling OSS Index analysis");
            pendingScannerResults.add(
                    ctx.callActivity(
                            OssIndexAnalysisActivity.class,
                            args,
                            protoConverter(AnalyzeProjectArgs.class),
                            protoConverter(AnalyzeProjectVulnsResultX.class),
                            scannerRetryPolicy));
        }

        // TODO: Trigger more analyzers.

        // TODO: Handle analyzer failures.
        //  We can still process partial results, but the process-project-analysis-results
        //  needs to know when something failed.
        ctx.logger().info("Waiting for results from {} scanners", pendingScannerResults.size());
        final List<AnalyzeProjectVulnsResultX> scannerResults = pendingScannerResults.stream()
                .map(Awaitable::await)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();

        final var processResultsArgsBuilder = ProcessProjectAnalysisResultsArgs.newBuilder();
        scannerResults.forEach(processResultsArgsBuilder::addResults);

        ctx.setStatus(STATUS_PROCESSING_VULN_ANALYSIS_RESULTS);
        ctx.logger().info("Scheduling processing of vulnerability analysis results");
        ctx.callActivity(
                ProcessProjectAnalysisResultsActivity.class,
                processResultsArgsBuilder.build(),
                protoConverter(ProcessProjectAnalysisResultsArgs.class),
                voidConverter(),
                defaultRetryPolicy()).await();

        ctx.logger().info("Scheduling policy evaluation");
        ctx.setStatus(STATUS_EVALUATING_POLICIES);
        ctx.callActivity(
                PolicyEvaluationTask.class,
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
                ProjectMetricsUpdateTask.class,
                UpdateProjectMetricsArgs.newBuilder()
                        .setProject(args.getProject())
                        .build(),
                protoConverter(UpdateProjectMetricsArgs.class),
                voidConverter(),
                defaultRetryPolicy()
                        .withMaxAttempts(6)).await();

        ctx.setStatus(STATUS_COMPLETED);
        return Optional.empty();
    }

    private AnalyzerStatuses getAnalyzerStatuses() {
        return withJdbiHandle(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);

            return AnalyzerStatuses.newBuilder()
                    .setInternalEnabled(dao.getOptionalValue(
                            SCANNER_INTERNAL_ENABLED, Boolean.class).orElse(false))
                    .setOssIndexEnabled(dao.getOptionalValue(
                            SCANNER_OSSINDEX_ENABLED, Boolean.class).orElse(false))
                    .build();
        });
    }

}