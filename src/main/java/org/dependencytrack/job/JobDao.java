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
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMethods;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@RegisterConstructorMapper(QueuedJob.class)
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
    List<QueuedJob> transitionStatus(@BindMethods Collection<JobStatusTransition> transitions);

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

}
