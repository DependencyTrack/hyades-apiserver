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

import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Update;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public class JobDao {

    private final Handle jdbiHandle;
    private final RowMapper<QueuedJob> queuedJobRowMapper;

    public JobDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
        this.queuedJobRowMapper = new QueuedJobRowMapper();
    }

    public List<QueuedJob> enqueueAll(final Collection<NewJob> newJobs) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "JOB" (
                  "STATUS"
                , "KIND"
                , "PRIORITY"
                , "SCHEDULED_FOR"
                , "ARGUMENTS"
                , "WORKFLOW_STEP_RUN_ID"
                , "CREATED_AT"
                ) VALUES (
                  'PENDING'
                , :kind
                , :priority
                , COALESCE(:scheduledFor, NOW())
                , :arguments
                , :workflowStepRunId
                , NOW())
                RETURNING *
                """);

        for (final NewJob newJob : newJobs) {
            preparedBatch
                    .bind("kind", newJob.kind())
                    .bind("priority", newJob.priority())
                    .bind("scheduledFor", newJob.scheduledFor())
                    .bind("arguments", newJob.arguments())
                    .bind("workflowStepRunId", newJob.workflowStepRunId())
                    .add();
        }

        return preparedBatch
                .registerArgument(new JobArgumentsArgument.Factory())
                .executePreparedBatch("*")
                .map(queuedJobRowMapper)
                .list();
    }

    public Optional<QueuedJob> requeueForRetry(final QueuedJob queuedJob, final Duration delay, final String failureReason) {
        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE_POLL" AS (
                    SELECT "ID"
                      FROM "JOB"
                     WHERE "ID" = :jobId
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
                """);

        return update
                .bind("jobId", queuedJob.id())
                .bind("delay", delay)
                .bind("failureReason", failureReason)
                .executeAndReturnGeneratedKeys("*")
                .map(queuedJobRowMapper)
                .findOne();
    }

    public Optional<QueuedJob> poll(final String kind) {
        return jdbiHandle.createUpdate("""
                        WITH "CTE_POLL" AS (
                            SELECT "ID"
                              FROM "JOB"
                             WHERE "KIND" = :kind
                               AND "STATUS" = ANY(CAST('{PENDING, PENDING_RETRY}' AS JOB_STATUS[]))
                               AND "SCHEDULED_FOR" <= NOW()
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
                .bind("kind", kind)
                .executeAndReturnGeneratedKeys("*")
                .map(queuedJobRowMapper)
                .findOne();
    }

    public List<QueuedJob> transitionAll(final Collection<JobStatusTransition> transitions) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                UPDATE "JOB"
                   SET "STATUS" = :status
                     , "SCHEDULED_FOR" = COALESCE(:scheduledFor, "SCHEDULED_FOR")
                     , "FAILURE_REASON" = :failureReason
                     , "UPDATED_AT" = :timestamp
                 WHERE "ID" = :jobId
                   AND ("UPDATED_AT" IS NULL OR "UPDATED_AT" < :timestamp)
                RETURNING *
                """);

        for (final JobStatusTransition transition : transitions) {
            preparedBatch
                    .bind("status", transition.status())
                    .bind("failureReason", transition.failureReason())
                    .bind("scheduledFor", transition.scheduledFor())
                    .bind("timestamp", transition.timestamp())
                    .bind("jobId", transition.jobId())
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .map(queuedJobRowMapper)
                .list();
    }

}
