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
import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import org.dependencytrack.workflow.model.StartWorkflowOptions;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.WorkflowScheduleRow;
import org.dependencytrack.workflow.persistence.WorkflowScheduleRowTriggerUpdate;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

final class WorkflowScheduler implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowScheduler.class);

    private final WorkflowEngine engine;

    WorkflowScheduler(final WorkflowEngine engine) {
        this.engine = engine;
    }

    @Override
    public void run() {
        if (engine.state().isStoppingOrStopped()) {
            LOGGER.warn("Engine not running; Not scheduling workflows");
            return;
        }

        final var startOptionsByScheduleName = new HashMap<String, StartWorkflowOptions>();

        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final List<WorkflowScheduleRow> dueSchedules = dao.getAllDueSchedules();
            if (dueSchedules.isEmpty()) {
                LOGGER.debug("No due schedules");
                return;
            }

            for (final WorkflowScheduleRow dueSchedule : dueSchedules) {
                var startOptions = new StartWorkflowOptions(
                        dueSchedule.workflowName(), dueSchedule.workflowVersion());
                if (dueSchedule.priority() != null) {
                    startOptions = startOptions.withPriority(dueSchedule.priority());
                }
                if (dueSchedule.argument() != null) {
                    startOptions = startOptions.withArgument(dueSchedule.argument());
                }

                startOptionsByScheduleName.put(dueSchedule.name(), startOptions);
            }

            final List<WorkflowScheduleRowTriggerUpdate> triggerUpdates = dueSchedules.stream()
                    .map(schedule -> {
                        final Schedule cronSchedule;
                        try {
                            cronSchedule = Schedule.create(schedule.cron());
                        } catch (InvalidExpressionException e) {
                            LOGGER.warn("Failed to parse cron expression for %s".formatted(schedule), e);
                            return null;
                        }
                        final Instant nextTrigger = cronSchedule.next().toInstant();
                        return new WorkflowScheduleRowTriggerUpdate(schedule.id(), nextTrigger);
                    })
                    .filter(Objects::nonNull)
                    .toList();

            final List<WorkflowScheduleRow> updatedSchedules = dao.updateAllScheduleTriggers(triggerUpdates);
            if (LOGGER.isDebugEnabled()) {
                for (final WorkflowScheduleRow updatedSchedule : updatedSchedules) {
                    LOGGER.debug("Updated schedule: %s".formatted(updatedSchedule));
                }
            }
        });

        final List<CompletableFuture<Void>> startWorkflowFutures = startOptionsByScheduleName.entrySet().stream()
                .map(entry -> engine.startWorkflow(entry.getValue())
                        .thenAccept(run -> LOGGER.info("Started run %s for workflow %s/%d from schedule %s".formatted(
                                run.id(), run.workflowName(), run.workflowVersion(), entry.getKey()))))
                .toList();

        CompletableFuture.allOf(startWorkflowFutures.toArray(new CompletableFuture[0])).join();
    }

}
