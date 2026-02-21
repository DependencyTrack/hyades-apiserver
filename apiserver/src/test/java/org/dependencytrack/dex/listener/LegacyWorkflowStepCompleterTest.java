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
package org.dependencytrack.dex.listener;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;

class LegacyWorkflowStepCompleterTest extends PersistenceCapableTest {

    private LegacyWorkflowStepCompleter completer;

    @BeforeEach
    void beforeEach() {
        completer = new LegacyWorkflowStepCompleter();
    }

    @Test
    void shouldCompleteVulnAnalysisStepForCompletedRun() {
        final UUID token = UUID.randomUUID();
        qm.createWorkflowSteps(token);

        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, token.toString()))))));

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllWorkflowStatesForAToken(token)).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.BOM_CONSUMPTION);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING);
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.BOM_PROCESSING);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING);
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.VULN_ANALYSIS);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.COMPLETED);
                    assertThat(state.getFailureReason()).isNull();
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.POLICY_EVALUATION);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING);
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.METRICS_UPDATE);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING);
                });
    }

    @Test
    void shouldFailVulnAnalysisStepAndCancelChildrenForFailedRun() {
        final UUID token = UUID.randomUUID();
        qm.createWorkflowSteps(token);

        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.FAILED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, token.toString()))))));

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllWorkflowStatesForAToken(token)).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.BOM_CONSUMPTION);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING);
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.BOM_PROCESSING);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING);
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.VULN_ANALYSIS);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.FAILED);
                    assertThat(state.getFailureReason()).isEqualTo("Vulnerability analysis failed");
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.POLICY_EVALUATION);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.CANCELLED);
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(WorkflowStep.METRICS_UPDATE);
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.CANCELLED);
                });
    }

    @Test
    void shouldHandleMultipleRunsWithMixedStatuses() {
        final UUID tokenA = UUID.randomUUID();
        final UUID tokenB = UUID.randomUUID();
        qm.createWorkflowSteps(tokenA);
        qm.createWorkflowSteps(tokenB);

        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, tokenA.toString()))),
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.FAILED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, tokenB.toString()))))));

        qm.getPersistenceManager().evictAll();

        assertThat(qm.getWorkflowStateByTokenAndStep(tokenA, WorkflowStep.VULN_ANALYSIS))
                .satisfies(state -> {
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.COMPLETED);
                    assertThat(state.getFailureReason()).isNull();
                });
        assertThat(qm.getWorkflowStateByTokenAndStep(tokenA, WorkflowStep.POLICY_EVALUATION))
                .satisfies(state -> assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING));

        assertThat(qm.getWorkflowStateByTokenAndStep(tokenB, WorkflowStep.VULN_ANALYSIS))
                .satisfies(state -> {
                    assertThat(state.getStatus()).isEqualTo(WorkflowStatus.FAILED);
                    assertThat(state.getFailureReason()).isEqualTo("Vulnerability analysis failed");
                });
        assertThat(qm.getWorkflowStateByTokenAndStep(tokenB, WorkflowStep.POLICY_EVALUATION))
                .satisfies(state -> assertThat(state.getStatus()).isEqualTo(WorkflowStatus.CANCELLED));
        assertThat(qm.getWorkflowStateByTokenAndStep(tokenB, WorkflowStep.METRICS_UPDATE))
                .satisfies(state -> assertThat(state.getStatus()).isEqualTo(WorkflowStatus.CANCELLED));
    }

    @Test
    void shouldIgnoreRunsWithNonMatchingWorkflowName() {
        final UUID token = UUID.randomUUID();
        qm.createWorkflowSteps(token);

        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "repo-meta-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, token.toString()))))));

        assertThat(qm.getWorkflowStateByTokenAndStep(token, WorkflowStep.VULN_ANALYSIS))
                .satisfies(state -> assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING));
    }

    @Test
    void shouldIgnoreRunsWithNoLabels() {
        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        null))));
    }

    @Test
    void shouldIgnoreRunsWithMissingProjectUuid() {
        final UUID token = UUID.randomUUID();
        qm.createWorkflowSteps(token);

        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.of(WF_LABEL_BOM_UPLOAD_TOKEN, token.toString())))));

        assertThat(qm.getWorkflowStateByTokenAndStep(token, WorkflowStep.VULN_ANALYSIS))
                .satisfies(state -> assertThat(state.getStatus()).isEqualTo(WorkflowStatus.PENDING));
    }

    @Test
    void shouldIgnoreRunsWithMissingBomUploadToken() {
        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.of(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString())))));
    }

    @Test
    void shouldDoNothingForEmptyEvent() {
        completer.onEvent(new WorkflowRunsCompletedEvent(List.of()));
    }

    @Test
    void shouldHandleTokenWithNoMatchingWorkflowState() {
        completer.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, UUID.randomUUID().toString()))))));
    }

    private static WorkflowRunMetadata createRunMetadata(
            String workflowName,
            WorkflowRunStatus status,
            Map<String, String> labels) {
        return new WorkflowRunMetadata(
                UUID.randomUUID(),
                workflowName,
                1,
                null,
                "default",
                status,
                null,
                0,
                null,
                labels,
                Instant.now(),
                null,
                null,
                null);
    }

}