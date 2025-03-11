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

import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzerStatuses;
import org.dependencytrack.proto.workflow.payload.v1alpha1.EvalProjectPoliciesArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectVulnAnalysisResultsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsArgs;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.workflow.framework.Awaitable;
import org.dependencytrack.workflow.framework.RetryPolicy;
import org.dependencytrack.workflow.framework.WorkflowClient;
import org.dependencytrack.workflow.framework.WorkflowContext;
import org.dependencytrack.workflow.framework.WorkflowExecutor;
import org.dependencytrack.workflow.framework.annotation.Workflow;
import org.dependencytrack.workflow.framework.failure.ActivityFailureException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.framework.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Workflow(name = "analyze-project")
public class AnalyzeProjectWorkflow implements WorkflowExecutor<AnalyzeProjectArgs, Void> {

    public static final WorkflowClient<AnalyzeProjectArgs, Void> CLIENT =
            WorkflowClient.of(AnalyzeProjectWorkflow.class, protoConverter(AnalyzeProjectArgs.class), voidConverter());

    private static final String STATUS_ANALYZING_VULNS = "ANALYZING_VULNS";
    private static final String STATUS_PROCESSING_VULN_ANALYSIS_RESULTS = "PROCESSING_VULN_ANALYSIS_RESULTS";
    private static final String STATUS_EVALUATING_POLICIES = "EVALUATING_POLICIES";
    private static final String STATUS_UPDATING_METRICS = "UPDATING_METRICS";
    private static final String STATUS_COMPLETED = "COMPLETED";

    @Override
    public Optional<Void> execute(final WorkflowContext<AnalyzeProjectArgs, Void> ctx) throws Exception {
        final AnalyzeProjectArgs args = ctx.argument().orElseThrow();

        ctx.setStatus(STATUS_ANALYZING_VULNS);

        // Using side effect here because it's not worth scheduling
        // an asynchronous activity for this.
        final AnalyzerStatuses analyzerStatuses = ctx.sideEffect(
                "analyzer-statuses",
                /* argument */ null,
                protoConverter(AnalyzerStatuses.class),
                ignored -> getAnalyzerStatuses()).await().orElseThrow();

        final List<String> enabledAnalyzerNames =
                analyzerStatuses.getEnabledAnalyzersMap().entrySet().stream()
                        .filter(Map.Entry::getValue)
                        .map(Map.Entry::getKey)
                        .sorted()
                        .toList();

        final RetryPolicy vulnAnalyzerRetryPolicy = defaultRetryPolicy().withMaxAttempts(6);
        final var pendingVulnAnalyzerResults = new ArrayList<Awaitable<AnalyzeProjectVulnsResult>>();
        for (final String analyzerName : enabledAnalyzerNames) {
            ctx.logger().info("Scheduling vulnerability analysis with {}", analyzerName);
            pendingVulnAnalyzerResults.add(AnalyzeProjectVulnsActivity.CLIENT.call(
                    ctx,
                    AnalyzeProjectVulnsArgs.newBuilder()
                            .setProject(args.getProject())
                            .setAnalyzerName(analyzerName)
                            .build(),
                    vulnAnalyzerRetryPolicy));
        }

        final var vulnAnalysisResults = new ArrayList<ProcessProjectVulnAnalysisResultsArgs.Result>();
        ctx.logger().info("Waiting for results from {} scanners", pendingVulnAnalyzerResults.size());
        for (final Awaitable<AnalyzeProjectVulnsResult> pendingResult : pendingVulnAnalyzerResults) {
            try {
                pendingResult.await().ifPresent(
                        result -> vulnAnalysisResults.add(
                                ProcessProjectVulnAnalysisResultsArgs.Result.newBuilder()
                                        .setVdrFileMetadata(result.getVdrFileMetadata())
                                        .build()));
            } catch (ActivityFailureException e) {
                vulnAnalysisResults.add(
                        ProcessProjectVulnAnalysisResultsArgs.Result.newBuilder()
                                .setFailureReason(e.getMessage())
                                .build());
            }
        }

        ctx.setStatus(STATUS_PROCESSING_VULN_ANALYSIS_RESULTS);
        ctx.logger().info("Scheduling processing of vulnerability analysis results");
        ProcessProjectVulnAnalysisResultsActivity.CLIENT.call(
                ctx,
                ProcessProjectVulnAnalysisResultsArgs.newBuilder()
                        .setProject(args.getProject())
                        .addAllResults(vulnAnalysisResults)
                        .build(),
                defaultRetryPolicy()).await();

        ctx.logger().info("Scheduling policy evaluation");
        ctx.setStatus(STATUS_EVALUATING_POLICIES);
        PolicyEvaluationTask.ACTIVITY_CLIENT.call(
                ctx,
                EvalProjectPoliciesArgs.newBuilder()
                        .setProject(args.getProject())
                        .build(),
                defaultRetryPolicy()
                        .withMaxAttempts(6)).await();

        ctx.logger().info("Scheduling metrics update");
        ctx.setStatus(STATUS_UPDATING_METRICS);
        ProjectMetricsUpdateTask.ACTIVITY_CLIENT.call(
                ctx,
                UpdateProjectMetricsArgs.newBuilder()
                        .setProject(args.getProject())
                        .build(),
                defaultRetryPolicy()
                        .withMaxAttempts(6)).await();

        ctx.setStatus(STATUS_COMPLETED);
        return Optional.empty();
    }

    private AnalyzerStatuses getAnalyzerStatuses() {
        return withJdbiHandle(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);

            // TODO: Check all analyzers in a single query.
            return AnalyzerStatuses.newBuilder()
                    .putEnabledAnalyzers(
                            AnalyzerIdentity.INTERNAL_ANALYZER.name(),
                            dao.getOptionalValue(SCANNER_INTERNAL_ENABLED, Boolean.class).orElse(false))
                    .putEnabledAnalyzers(
                            AnalyzerIdentity.OSSINDEX_ANALYZER.name(),
                            dao.getOptionalValue(SCANNER_OSSINDEX_ENABLED, Boolean.class).orElse(false))
                    .putEnabledAnalyzers(
                            AnalyzerIdentity.SNYK_ANALYZER.name(),
                            dao.getOptionalValue(SCANNER_SNYK_ENABLED, Boolean.class).orElse(false))
                    // TODO: Trivy
                    .build();
        });
    }

}
