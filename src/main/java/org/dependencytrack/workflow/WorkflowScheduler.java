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

final class WorkflowScheduler implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowScheduler.class);

    private final WorkflowEngine workflowEngine;

    WorkflowScheduler(final WorkflowEngine workflowEngine) {
        this.workflowEngine = workflowEngine;
    }

    @Override
    public void run() {
        /*final var queuedJobs = new ArrayList<WorkflowRun>();

        useJdbiTransaction(handle -> {
            final var jobDao = new JobDao(handle);
            final var jobScheduleDao = new JobScheduleDao(handle);

            final List<JobSchedule> dueSchedules = jobScheduleDao.getAllDue();
            if (dueSchedules.isEmpty()) {
                LOGGER.debug("No due schedules");
                return;
            }

            final var jobsToQueue = dueSchedules.stream()
                    .map(schedule -> new NewJob(schedule.jobKind())
                            .withPriority(schedule.jobPriority()))
                    .toList();

            queuedJobs.addAll(jobDao.enqueueAll(jobsToQueue));
            if (LOGGER.isDebugEnabled()) {
                for (final QueuedJob queuedJob : queuedJobs) {
                    LOGGER.debug("Queued %s".formatted(queuedJob));
                }
            }

            final List<JobScheduleTriggerUpdate> triggerUpdates = dueSchedules.stream()
                    .map(schedule -> {
                        final Schedule cronSchedule;
                        try {
                            cronSchedule = Schedule.create(schedule.cron());
                        } catch (InvalidExpressionException e) {
                            LOGGER.warn("Failed to parse cron expression for %s".formatted(schedule), e);
                            return null;
                        }
                        final Instant nextTrigger = cronSchedule.next().toInstant();
                        return new JobScheduleTriggerUpdate(schedule.id(), nextTrigger);
                    })
                    .filter(Objects::nonNull)
                    .toList();
            final List<JobSchedule> updatedSchedules = jobScheduleDao.updateAllTriggers(triggerUpdates);
            if (LOGGER.isDebugEnabled()) {
                for (final JobSchedule updatedSchedule : updatedSchedules) {
                    LOGGER.debug("Updated schedule: %s".formatted(updatedSchedule));
                }
            }
        });

        workflowEngine.dispatchEvents(queuedJobs);*/
    }

    public void shutdown() {

    }

}
