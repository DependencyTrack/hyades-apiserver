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
package org.dependencytrack.job;

import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMappers;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMethods;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@RegisterConstructorMappers(value = {
        @RegisterConstructorMapper(QueuedJob.class),
        @RegisterConstructorMapper(JobSchedule.class)})
public interface JobDao {

    @SqlBatch("""
            INSERT INTO "JOB"(
              "STATUS"
            , "KIND"
            , "PRIORITY"
            , "SCHEDULED_FOR"
            , "PAYLOAD_TYPE"
            , "PAYLOAD"
            , "WORKFLOW_STEP_RUN_ID"
            , "CREATED_AT"
            ) VALUES (
              'PENDING'
            , :kind
            , :priority
            , COALESCE(:scheduledFor, NOW())
            , :payloadType
            , :payload
            , :workflowStepRunId
            , NOW())
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    List<QueuedJob> enqueueAll(@BindMethods Collection<NewJob> newJobs);

    record JobStatusTransition(long jobId, JobStatus status, String failureReason, Instant timestamp) {
    }

    @SqlBatch("""
            UPDATE "JOB"
               SET "STATUS" = :status
                 , "FAILURE_REASON" = :failureReason
                 , "UPDATED_AT" = :timestamp
             WHERE "ID" = :jobId
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    List<QueuedJob> transitionStatuses(@BindMethods Collection<JobStatusTransition> transitions);

    @SqlUpdate("""
            WITH "CTE_POLL" AS (
                SELECT "ID"
                  FROM "JOB"
                 WHERE "STATUS" NOT IN ('COMPLETED', 'FAILED', 'RUNNING')
                   AND "SCHEDULED_FOR" <= NOW()
                   AND "KIND" = ANY(:kinds)
                 ORDER BY "PRIORITY" DESC NULLS LAST
                        , "SCHEDULED_FOR"
                        , "CREATED_AT"
                   FOR UPDATE
                  SKIP LOCKED
                 LIMIT 1)
            UPDATE "JOB"
               SET "STATUS" = 'RUNNING'
                 , "STARTED_AT" = COALESCE("STARTED_AT", NOW())
                 , "ATTEMPTS" = COALESCE("ATTEMPTS", 0) + 1
              FROM "CTE_POLL"
             WHERE "JOB"."ID" = "CTE_POLL"."ID"
            RETURNING "JOB".*
            """)
    @GetGeneratedKeys("*")
    QueuedJob poll(@Bind Set<String> kinds);

    @SqlUpdate("""
            WITH "CTE_POLL" AS (
                SELECT "ID"
                  FROM "JOB"
                 WHERE "ID" = :job.id
                   AND "STATUS" = 'RUNNING'
                   FOR UPDATE
                  SKIP LOCKED
                 LIMIT 1)
            UPDATE "JOB"
               SET "STATUS" = 'PENDING_RETRY'
                 , "SCHEDULED_FOR" = NOW() + :delay
                 , "UPDATED_AT" = NOW()
                 , "ATTEMPTS" = "ATTEMPTS" + 1
                 , "FAILURE_REASON" = :failureReason
              FROM "CTE_POLL"
             WHERE "JOB"."ID" = "CTE_POLL"."ID"
            RETURNING "JOB".*
            """)
    @GetGeneratedKeys("*")
    QueuedJob requeueForRetry(@BindMethods("job") QueuedJob job, @Bind Duration delay, @Bind String failureReason);

    @SqlBatch("""
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
            """)
    @GetGeneratedKeys("*")
    List<JobSchedule> createSchedules(@BindMethods Collection<NewJobSchedule> newSchedules);

    @SqlQuery("""
            SELECT *
              FROM "JOB_SCHEDULE"
             WHERE "NEXT_TRIGGER" <= NOW()
               FOR UPDATE
            """)
    List<JobSchedule> getDueSchedules();

    record ScheduleTriggerUpdate(long scheduleId, Instant nextTrigger) {
    }

    @SqlBatch("""
            UPDATE "JOB_SCHEDULE"
               SET "LAST_TRIGGER" = NOW()
                 , "NEXT_TRIGGER" = :nextTrigger
                 , "UPDATED_AT" = NOW()
             WHERE "ID" = :scheduleId
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    List<JobSchedule> updateScheduleTriggers(@BindMethods Collection<ScheduleTriggerUpdate> triggerUpdates);

}
