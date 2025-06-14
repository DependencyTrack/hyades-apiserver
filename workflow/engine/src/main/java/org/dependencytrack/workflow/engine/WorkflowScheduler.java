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
package org.dependencytrack.workflow.engine;

import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import org.dependencytrack.workflow.engine.api.CreateWorkflowRunRequest;
import org.dependencytrack.workflow.engine.api.WorkflowSchedule;
import org.dependencytrack.workflow.engine.persistence.WorkflowScheduleDao;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

final class WorkflowScheduler implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowScheduler.class);

    private final WorkflowEngineImpl engine;
    private final Jdbi jdbi;

    WorkflowScheduler(final WorkflowEngineImpl engine, final Jdbi jdbi) {
        this.engine = engine;
        this.jdbi = jdbi;
    }

    @Override
    public void run() {
        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowScheduleDao(handle);

            final List<WorkflowSchedule> dueSchedules = dao.getDueSchedulesForUpdate();
            if (dueSchedules.isEmpty()) {
                LOGGER.debug("No due schedules found");
                return;
            } else if (LOGGER.isDebugEnabled()) {
                for (final WorkflowSchedule schedule : dueSchedules) {
                    LOGGER.debug("Schedule {} is due as of {}", schedule.name(), schedule.nextFireAt());
                }
            }

            final var now = Instant.now();
            final var scheduleRunOptions = new ArrayList<CreateWorkflowRunRequest>(dueSchedules.size());
            final var nextFireAtByName = new HashMap<String, Instant>(dueSchedules.size());

            for (final WorkflowSchedule schedule : dueSchedules) {
                try {
                    final Schedule cronSchedule = Schedule.create(schedule.cron());
                    final Instant nextFireAt = cronSchedule.next(Date.from(now)).toInstant();
                    nextFireAtByName.put(schedule.name(), nextFireAt);
                } catch (InvalidExpressionException e) {
                    LOGGER.warn(
                            "Failed to parse cron expression {} of schedule {}; Skipping",
                            schedule.cron(), schedule.name(), e);
                    continue;
                }

                final Map<String, String> labels = new HashMap<>();
                if (schedule.labels() != null) {
                    labels.putAll(schedule.labels());
                }
                labels.put("schedule", schedule.name());

                scheduleRunOptions.add(new CreateWorkflowRunRequest(
                        schedule.workflowName(),
                        schedule.workflowVersion(),
                        schedule.concurrencyGroupId(),
                        schedule.priority(),
                        labels,
                        schedule.argument()));
            }

            // TODO: This should share the same transaction as the current handle.
            final List<UUID> scheduledRunIds = engine.createRuns(scheduleRunOptions);
            assert scheduledRunIds.size() == dueSchedules.size();

            if (LOGGER.isDebugEnabled()) {
                for (final Map.Entry<String, Instant> entry : nextFireAtByName.entrySet()) {
                    LOGGER.debug("Updating next fire for schedule {}: {}", entry.getKey(), entry.getValue());
                }
            }

            final int updatedSchedules = dao.updateScheduleNextFireAt(nextFireAtByName);
            assert updatedSchedules == dueSchedules.size();
        });
    }

}
