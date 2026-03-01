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

import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.DexEngineEventListener;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.persistence.jdbi.WorkflowDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * A {@link DexEngineEventListener} that handles completion of legacy {@link WorkflowState}s
 * upon termination of dex workflow runs.
 *
 * @since 5.7.0
 * @deprecated To be removed once the legacy workflow mechanism is fully phased out.
 */
@Deprecated(since = "5.7.0", forRemoval = true)
public final class LegacyWorkflowStepCompleter implements WorkflowRunsCompletedEventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(LegacyWorkflowStepCompleter.class);

    @Override
    public void onEvent(WorkflowRunsCompletedEvent event) {
        final var relevantRuns = new ArrayList<RelevantRun>();

        for (final WorkflowRunMetadata runMetadata : event.completedRuns()) {
            if (!"analyze-project".equals(runMetadata.workflowName())) {
                continue;
            }

            final Map<String, String> labels = runMetadata.labels();
            if (labels == null) {
                continue;
            }

            final UUID projectUuid = Optional
                    .ofNullable(labels.get(WF_LABEL_PROJECT_UUID))
                    .map(UUID::fromString)
                    .orElse(null);
            final UUID workflowToken = Optional
                    .ofNullable(labels.get(WF_LABEL_BOM_UPLOAD_TOKEN))
                    .map(UUID::fromString)
                    .orElse(null);
            if (projectUuid != null && workflowToken != null) {
                relevantRuns.add(new RelevantRun(projectUuid, workflowToken, runMetadata.status()));
            }
        }

        if (relevantRuns.isEmpty()) {
            return;
        }

        useJdbiTransaction(handle -> {
            final var workflowDao = handle.attach(WorkflowDao.class);

            final List<WorkflowState> updatedWorkflowStates = workflowDao.updateAllStates(
                    WorkflowStep.VULN_ANALYSIS,
                    relevantRuns.stream()
                            .map(RelevantRun::workflowToken)
                            .toList(),
                    relevantRuns.stream()
                            .map(run -> run.status() == WorkflowRunStatus.COMPLETED
                                    ? WorkflowStatus.COMPLETED
                                    : WorkflowStatus.FAILED)
                            .toList(),
                    relevantRuns.stream()
                            .map(run -> run.status() != WorkflowRunStatus.COMPLETED
                                    ? "Vulnerability analysis failed"
                                    : null)
                            .toList());

            final List<UUID> failedStepTokens = updatedWorkflowStates.stream()
                    .filter(step -> step.getStatus() == WorkflowStatus.FAILED)
                    .map(WorkflowState::getToken)
                    .toList();
            if (!failedStepTokens.isEmpty()) {
                LOGGER.warn("Cancelling children of {} failed workflow steps", failedStepTokens.size());
                workflowDao.cancelAllChildren(WorkflowStep.VULN_ANALYSIS, failedStepTokens);
            }

            final List<UUID> completedTokens = updatedWorkflowStates.stream()
                    .filter(s -> s.getStatus() == WorkflowStatus.COMPLETED)
                    .map(WorkflowState::getToken)
                    .toList();
            if (!completedTokens.isEmpty()) {
                workflowDao.updateAllStates(
                        WorkflowStep.POLICY_EVALUATION,
                        completedTokens,
                        Collections.nCopies(completedTokens.size(), WorkflowStatus.COMPLETED),
                        Collections.nCopies(completedTokens.size(), null));
                workflowDao.updateAllStates(
                        WorkflowStep.METRICS_UPDATE,
                        completedTokens,
                        Collections.nCopies(completedTokens.size(), WorkflowStatus.COMPLETED),
                        Collections.nCopies(completedTokens.size(), null));
            }
        });
    }

    private record RelevantRun(UUID projectUuid, UUID workflowToken, WorkflowRunStatus status) {
    }

}
