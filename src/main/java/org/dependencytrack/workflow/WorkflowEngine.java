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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class WorkflowEngine {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngine.class);
    private static final WorkflowEngine INSTANCE = new WorkflowEngine();

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    // TODO: Listeners for workflow run state change?
    // TODO: Listeners for workflow step run state change?
    // TODO: Execute workflow steps by enqueueing jobs.

    public void deploy(final WorkflowSpec spec) {
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            LOGGER.info("Deploying workflow %s v%d".formatted(spec.name(), spec.version()));
            final Workflow workflow = dao.createWorkflow(new NewWorkflow(spec.name(), spec.version()));

            final var workflowStepByName = new HashMap<String, WorkflowStep>(spec.stepSpecs().size());
            final var workflowStepDependencies = new HashMap<String, Set<String>>();
            for (final WorkflowStepSpec stepSpec : spec.stepSpecs()) {
                final WorkflowStep step = dao.createStep(new NewWorkflowStep(workflow.id(), stepSpec.name()));
                workflowStepByName.put(step.name(), step);

                if (!stepSpec.stepDependencies().isEmpty()) {
                    workflowStepDependencies.put(step.name(), stepSpec.stepDependencies());
                }
            }

            for (final Map.Entry<String, Set<String>> entry : workflowStepDependencies.entrySet()) {
                final String stepName = entry.getKey();
                final Set<String> dependencyNames = entry.getValue();

                final WorkflowStep step = workflowStepByName.get(stepName);
                for (final String dependencyName : dependencyNames) {
                    final WorkflowStep dependencyStep = workflowStepByName.get(dependencyName);
                    dao.createStepDependency(step.id(), dependencyStep.id());
                }
            }
        });
    }

    public WorkflowRunView startWorkflow(final StartWorkflowOptions options) {
        requireNonNull(options);

        return inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final Workflow workflow = dao.getWorkflowByNameAndVersion(options.name(), options.version());
            if (workflow == null) {
                throw new NoSuchElementException("Workflow %s/%d does not exist".formatted(options.name(), options.version()));
            }

            final List<WorkflowStep> steps = dao.getStepsByWorkflow(workflow);
            if (steps == null || steps.isEmpty()) {
                throw new IllegalStateException("Workflow %s/%d has no steps".formatted(workflow.name(), workflow.version()));
            }

            LOGGER.info("Starting workflow %s/%d".formatted(workflow.name(), workflow.version()));
            final WorkflowRun workflowRun = dao.createWorkflowRun(workflow, UUID.randomUUID());
            final List<WorkflowStepRunView> stepRunViews = steps.stream()
                    .map(step -> {
                        final WorkflowStepRun stepRun = dao.createStepRun(workflowRun, step);
                        return new WorkflowStepRunView(
                                step.name(),
                                stepRun.status(),
                                stepRun.createdAt(),
                                stepRun.updatedAt(),
                                stepRun.startedAt());
                    })
                    .toList();

            return new WorkflowRunView(
                    workflow.name(),
                    workflow.version(),
                    workflowRun.token(),
                    workflowRun.priority(),
                    workflowRun.status(),
                    workflowRun.createdAt(),
                    workflowRun.startedAt(),
                    stepRunViews);
        });
    }

    public Optional<WorkflowRunView> getWorkflowRun(final UUID token) {
        return inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final WorkflowRunView workflowRun = dao.getWorkflowRunViewByToken(token);
            if (workflowRun == null) {
                return Optional.empty();
            }

            final List<WorkflowStepRunView> stepRuns = dao.getStepRunViewsByToken(token);

            return Optional.of(new WorkflowRunView(
                    workflowRun.workflowName(),
                    workflowRun.workflowVersion(),
                    workflowRun.token(),
                    workflowRun.priority(),
                    workflowRun.status(),
                    workflowRun.createdAt(),
                    workflowRun.startedAt(),
                    stepRuns));
        });
    }

    public Optional<ClaimedWorkflowStepRun> claimStepRun(final UUID token, String stepName) {
        return inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);
            final ClaimedWorkflowStepRun claimedStepRun = dao.claimStepRun(token, stepName);
            return Optional.ofNullable(claimedStepRun);
        });
    }

    public void completeStepRun(final ClaimedWorkflowStepRun stepRun) {
        useJdbiTransaction(handle -> {
            // TODO: Handle illegal transitions.
            final var dao = handle.attach(WorkflowDao.class);
            dao.transitionStepRun(stepRun.id(), WorkflowStepRunStatus.COMPLETED);
        });
    }

    public void failStepRun(final ClaimedWorkflowStepRun stepRun) {
        useJdbiTransaction(handle -> {
            // TODO: Handle illegal transitions.
            final var dao = handle.attach(WorkflowDao.class);
            dao.transitionStepRun(stepRun.id(), WorkflowStepRunStatus.FAILED);
            final int cancelledStepRuns = dao.cancelDependantStepRuns(stepRun.workflowRunId(), stepRun.stepId());
            LOGGER.info("Cancelled %d dependant step runs".formatted(cancelledStepRuns));
        });
    }

    public void restartStepRun(final UUID token, String stepName) {
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);
            final WorkflowStepRun stepRun = dao.getStepRunForUpdateByTokenAndName(token, stepName);
            if (stepRun == null) {
                throw new NoSuchElementException("No step run exists for token %s and name %s".formatted(token, stepName));
            }

            if (!stepRun.status().canTransition(WorkflowStepRunStatus.PENDING)) {
                throw new IllegalStateException("Can not transition step run from %s to %s".formatted(
                        stepRun.status(), WorkflowStepRunStatus.PENDING));
            }

            final boolean transitioned = dao.transitionStepRun(stepRun.id(), WorkflowStepRunStatus.PENDING);
            if (!transitioned) {
                throw new IllegalStateException("Did not transition step run from %s to %s".formatted(
                        stepRun.status(), WorkflowStepRunStatus.PENDING));
            }
        });
    }

}
