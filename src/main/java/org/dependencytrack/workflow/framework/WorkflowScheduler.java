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
package org.dependencytrack.workflow.framework;

import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import org.dependencytrack.workflow.framework.persistence.WorkflowDao;
import org.dependencytrack.workflow.framework.persistence.model.WorkflowScheduleRow;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

final class WorkflowScheduler implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowScheduler.class);

    private final WorkflowEngine engine;
    private final Jdbi jdbi;

    WorkflowScheduler(final WorkflowEngine engine, final Jdbi jdbi) {
        this.engine = engine;
        this.jdbi = jdbi;
    }

    @Override
    public void run() {
        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final List<WorkflowScheduleRow> dueSchedules = dao.getDueSchedulesForUpdate();
            if (dueSchedules.isEmpty()) {
                LOGGER.debug("No due schedules found");
                return;
            } else if (LOGGER.isDebugEnabled()) {
                for (final WorkflowScheduleRow schedule : dueSchedules) {
                    LOGGER.debug("Schedule {} is due as of {}", schedule.name(), schedule.nextFireAt());
                }
            }

            final var now = Instant.now();
            final var scheduleRunOptions = new ArrayList<ScheduleWorkflowRunOptions>(dueSchedules.size());
            final var nextFireAtByName = new HashMap<String, Instant>(dueSchedules.size());

            for (final WorkflowScheduleRow schedule : dueSchedules) {
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

                final Set<String> tags = new HashSet<>();
                if (schedule.tags() != null) {
                    tags.addAll(schedule.tags());
                }
                tags.add("scheduled");
                tags.add("schedule=" + schedule.name());

                scheduleRunOptions.add(new ScheduleWorkflowRunOptions(
                        schedule.workflowName(),
                        schedule.workflowVersion(),
                        schedule.concurrencyGroupId(),
                        schedule.priority(),
                        tags,
                        schedule.argument()));
            }

            // TODO: This should share the same transaction as the current handle.
            final List<UUID> scheduledRunIds = engine.scheduleWorkflowRuns(scheduleRunOptions);
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
