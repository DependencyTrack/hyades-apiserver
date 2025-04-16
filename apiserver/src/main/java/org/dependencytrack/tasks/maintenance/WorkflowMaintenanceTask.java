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
package org.dependencytrack.tasks.maintenance;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.maintenance.WorkflowMaintenanceEvent;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.WorkflowDao;
import org.jdbi.v3.core.Handle;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static net.javacrumbs.shedlock.core.LockAssert.assertLocked;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_WORKFLOW_RETENTION_HOURS;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_WORKFLOW_STEP_TIMEOUT_MINUTES;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * @since 5.6.0
 */
public class WorkflowMaintenanceTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(WorkflowMaintenanceTask.class);

    @Override
    public void inform(final Event event) {
        if (!(event instanceof WorkflowMaintenanceEvent)) {
            return;
        }

        final long startTimeNs = System.nanoTime();
        try (final Handle jdbiHandle = openJdbiHandle()) {
            LOGGER.info("Starting workflow maintenance");
            final Statistics statistics = executeWithLock(
                    getLockConfigForTask(WorkflowMaintenanceTask.class),
                    () -> informLocked(jdbiHandle));
            if (statistics == null) {
                LOGGER.info("Task is locked by another instance; Skipping");
                return;
            }

            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.info("Completed in %s: %s".formatted(taskDuration, statistics));
        } catch (Throwable e) {
            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.error("Failed to complete after %s".formatted(taskDuration), e);
        }
    }

    private record Statistics(
            Duration retentionDuration,
            Duration stepTimeoutDuration,
            int stepsTimedOut,
            int stepsFailed,
            int stepsCancelled,
            int workflowsDeleted) {
    }

    private Statistics informLocked(final Handle jdbiHandle) {
        assertLocked();

        final var configPropertyDao = jdbiHandle.attach(ConfigPropertyDao.class);
        final var workflowDao = jdbiHandle.attach(WorkflowDao.class);

        final Integer retentionHours = configPropertyDao.getValue(MAINTENANCE_WORKFLOW_RETENTION_HOURS, Integer.class);
        final Duration retentionDuration = Duration.ofHours(retentionHours);

        final Integer stepTimeoutMinutes = configPropertyDao.getValue(MAINTENANCE_WORKFLOW_STEP_TIMEOUT_MINUTES, Integer.class);
        final Duration stepTimeoutDuration = Duration.ofMinutes(stepTimeoutMinutes);

        final int numStepsTimedOut = workflowDao.transitionAllPendingStepsToTimedOutForTimeout(stepTimeoutDuration);
        if (numStepsTimedOut > 0) {
            LOGGER.warn("Transitioned %d workflow step(s) from %s to %s for timeout %s"
                    .formatted(numStepsTimedOut, WorkflowStatus.PENDING, WorkflowStatus.TIMED_OUT, stepTimeoutDuration));
        }

        final var failedStepsResult = new Object() {
            int numStepsFailed = 0;
            int numStepsCancelled = 0;
        };
        jdbiHandle.useTransaction(ignored -> {
            final List<Long> failedStepIds = workflowDao.transitionAllTimedOutStepsToFailedForTimeout(stepTimeoutDuration);
            if (failedStepIds.isEmpty()) {
                return;
            }

            failedStepsResult.numStepsFailed = failedStepIds.size();
            LOGGER.warn("Transitioned %d workflow step(s) from %s to %s for timeout %s"
                    .formatted(failedStepsResult.numStepsFailed, WorkflowStatus.TIMED_OUT, WorkflowStatus.FAILED, stepTimeoutDuration));

            failedStepsResult.numStepsCancelled = Arrays.stream(workflowDao.cancelAllChildrenByParentStepIdAnyOf(failedStepIds)).sum();
            if (failedStepsResult.numStepsCancelled > 0) {
                LOGGER.warn("Transitioned %d workflow step(s) to %s because their parent steps transitioned to %s"
                        .formatted(failedStepsResult.numStepsCancelled, WorkflowStatus.CANCELLED, WorkflowStatus.FAILED));
            }
        });

        final int numWorkflowsDeleted = workflowDao.deleteAllForRetention(retentionDuration);

        return new Statistics(
                retentionDuration,
                stepTimeoutDuration,
                numStepsTimedOut,
                failedStepsResult.numStepsFailed,
                failedStepsResult.numStepsCancelled,
                numWorkflowsDeleted);
    }

}
