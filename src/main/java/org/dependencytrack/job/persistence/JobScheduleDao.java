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
package org.dependencytrack.job.persistence;

import org.dependencytrack.job.JobSchedule;
import org.dependencytrack.job.NewJobSchedule;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.PreparedBatch;

import java.util.Collection;
import java.util.List;

public class JobScheduleDao {

    private final Handle jdbiHandle;
    private final RowMapper<JobSchedule> jobScheduleRowMapper;

    public JobScheduleDao(Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
        this.jobScheduleRowMapper = ConstructorMapper.of(JobSchedule.class);
    }

    public List<JobSchedule> createAll(final Collection<NewJobSchedule> newSchedules) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "JOB_SCHEDULE" (
                  "NAME"
                , "CRON"
                , "JOB_KIND"
                , "JOB_PRIORITY"
                , "CREATED_AT"
                , "NEXT_TRIGGER"
                ) VALUES (
                  :name
                , :cron
                , :jobKind
                , :jobPriority
                , NOW()
                , :nextTrigger
                )
                ON CONFLICT("NAME") DO NOTHING
                """);

        for (final NewJobSchedule newSchedule : newSchedules) {
            preparedBatch
                    .bind("name", newSchedule.name())
                    .bind("cron", newSchedule.cron())
                    .bind("jobKind", newSchedule.jobKind())
                    .bind("jobPriority", newSchedule.jobPriority())
                    .bind("nextTrigger", newSchedule.nextTrigger())
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .map(jobScheduleRowMapper)
                .list();
    }

    public List<JobSchedule> getAllDue() {
        return jdbiHandle.createQuery("""
                        SELECT *
                          FROM "JOB_SCHEDULE"
                         WHERE "NEXT_TRIGGER" <= NOW()
                           FOR UPDATE
                        """)
                .map(jobScheduleRowMapper)
                .list();
    }

    public List<JobSchedule> updateAllTriggers(final Collection<JobScheduleTriggerUpdate> triggerUpdates) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                UPDATE "JOB_SCHEDULE"
                   SET "LAST_TRIGGER" = NOW()
                     , "NEXT_TRIGGER" = :nextTrigger
                     , "UPDATED_AT" = NOW()
                 WHERE "ID" = :scheduleId
                RETURNING *
                """);

        for (final JobScheduleTriggerUpdate triggerUpdate : triggerUpdates) {
            preparedBatch
                    .bind("nextTrigger", triggerUpdate.nextTrigger())
                    .bind("scheduleId", triggerUpdate.scheduleId())
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .map(jobScheduleRowMapper)
                .list();
    }

}
