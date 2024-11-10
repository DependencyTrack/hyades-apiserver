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
package org.dependencytrack.workflow.persistence;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class WorkflowDao {

    private final Handle jdbiHandle;
    private final RowMapper<PolledWorkflowTaskRow> polledWorkflowTaskRowMapper;
    private final RowMapper<WorkflowTaskRow> queuedWorkflowTaskRowMapper;

    public WorkflowDao(Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
        this.polledWorkflowTaskRowMapper = new PolledWorkflowTaskRowMapper();
        this.queuedWorkflowTaskRowMapper = new WorkflowTaskRowMapper();
    }

    public List<WorkflowRunRow> createAllRuns(final Collection<NewWorkflowRunRow> newRuns) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_RUN" (
                  "ID"
                , "WORKFLOW_NAME"
                , "WORKFLOW_VERSION"
                , "STATUS"
                , "PRIORITY"
                , "UNIQUE_KEY"
                , "CREATED_AT"
                ) VALUES (
                  :id
                , :workflowName
                , :workflowVersion
                , 'PENDING'
                , :priority
                , :uniqueKey
                , :createdAt
                )
                ON CONFLICT ("ID") DO NOTHING
                RETURNING *
                """);

        for (final NewWorkflowRunRow newRun : newRuns) {
            preparedBatch
                    .bindMethods(newRun)
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .list();
    }

    public WorkflowRunRow createRun(final NewWorkflowRunRow newRun) {
        final List<WorkflowRunRow> createdRuns = createAllRuns(List.of(newRun));
        if (!createdRuns.isEmpty()) {
            return createdRuns.getFirst();
        }

        return null;
    }

    public List<UUID> updateAllRuns(final Collection<WorkflowRunRowUpdate> runUpdates) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                WITH "CTE_RUN" AS (
                    SELECT "ID"
                      FROM "WORKFLOW_RUN"
                     WHERE "ID" = :id
                       FOR UPDATE
                     LIMIT 1)
                UPDATE "WORKFLOW_RUN"
                   SET "STATUS" = :status
                     , "RESULT" = :result
                     , "FAILURE_DETAILS" = :failureDetails
                     , "UPDATED_AT" = NOW()
                     , "STARTED_AT" = :startedAt
                     , "ENDED_AT" = :endedAt
                  FROM "CTE_RUN"
                 WHERE "WORKFLOW_RUN"."ID" = "CTE_RUN"."ID"
                RETURNING "WORKFLOW_RUN"."ID"
                """);

        for (final WorkflowRunRowUpdate runUpdate : runUpdates) {
            preparedBatch
                    .bindMethods(runUpdate)
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .mapTo(UUID.class)
                .list();
    }

    public List<WorkflowRunRow> getWorkflowRunsById(final Collection<UUID> ids) {
        final Query query = jdbiHandle.createQuery("""
                SELECT *
                  FROM "WORKFLOW_RUN"
                 WHERE "ID" = ANY(:ids)
                """);

        return query
                .bindArray("ids", UUID.class, ids)
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .list();
    }

    public boolean doesRunExist(final UUID runId) {
        final Query query = jdbiHandle.createQuery("""
                SELECT EXISTS(
                    SELECT 1
                      FROM "WORKFLOW_RUN"
                     WHERE "ID" = :id)
                """);

        return query
                .bind("id", runId)
                .mapTo(Boolean.class)
                .one();
    }

    public Set<UUID> createWorkflowRunLogEntries(
            final Collection<NewWorkflowRunLogEntryRow> entries) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_RUN_LOG" (
                  "WORKFLOW_RUN_ID"
                , "EVENT_ID"
                , "TIMESTAMP"
                , "EVENT_TYPE"
                , "ACTIVITY_RUN_ID"
                , "EVENT"
                ) VALUES (
                  :workflowRunId
                , :eventId
                , :timestamp
                , CAST(:eventType AS WORKFLOW_EVENT_TYPE)
                , :activityRunId
                , :event
                )
                ON CONFLICT ("WORKFLOW_RUN_ID", "TIMESTAMP", "EVENT_ID") DO NOTHING
                RETURNING "EVENT_ID"
                """);

        for (final NewWorkflowRunLogEntryRow entry : entries) {
            preparedBatch
                    .bindMethods(entry)
                    .add();
        }

        return preparedBatch
                .registerArgument(new WorkflowEventArgument.Factory())
                .executePreparedBatch("*")
                .mapTo(UUID.class)
                .set();
    }

    public List<WorkflowEvent> getWorkflowRunLog(final UUID workflowRunId) {
        final Query query = jdbiHandle.createQuery("""
                SELECT "EVENT"
                  FROM "WORKFLOW_RUN_LOG"
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                 ORDER BY "TIMESTAMP"
                """);

        return query
                .bind("workflowRunId", workflowRunId)
                .map(new WorkflowEventColumnMapper())
                .list();
    }

    public boolean hasActivityCompletionLog(
            final UUID workflowRunId,
            final UUID activityRunId,
            final Instant upToTimestamp) {
        return jdbiHandle.createQuery("""
                        SELECT EXISTS(
                            SELECT 1
                              FROM "WORKFLOW_RUN_LOG"
                             WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                               AND "ACTIVITY_RUN_ID" = :activityRunId
                               AND "EVENT_TYPE" = ANY(CAST('{ACTIVITY_RUN_COMPLETED, ACTIVITY_RUN_FAILED}' AS WORKFLOW_EVENT_TYPE[]))
                               AND "TIMESTAMP" <= :upToTimestamp)
                        """)
                .bind("workflowRunId", workflowRunId)
                .bind("activityRunId", activityRunId)
                .bind("upToTimestamp", upToTimestamp)
                .mapTo(Boolean.class)
                .one();
    }

    public List<UUID> createAllTasks(final Collection<NewWorkflowTaskRow> newTasks) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_TASK" (
                  "ID"
                , "STATUS"
                , "QUEUE"
                , "PRIORITY"
                , "SCHEDULED_FOR"
                , "ARGUMENTS"
                , "WORKFLOW_RUN_ID"
                , "ACTIVITY_RUN_ID"
                , "ACTIVITY_NAME"
                , "ACTIVITY_INVOCATION_ID"
                , "INVOKING_TASK_ID"
                , "CREATED_AT"
                ) VALUES (
                  :id
                , 'PENDING'
                , :queue
                , :priority
                , COALESCE(:scheduledFor, NOW())
                , :arguments
                , :workflowRunId
                , :activityRunId
                , :activityName
                , :activityInvocationId
                , :invokingTaskId
                , NOW())
                RETURNING "ID"
                """);

        for (final NewWorkflowTaskRow newTask : newTasks) {
            preparedBatch
                    .bind("id", newTask.id())
                    .bind("queue", newTask.queue())
                    .bind("priority", newTask.priority())
                    .bind("scheduledFor", newTask.scheduledFor())
                    .bind("arguments", newTask.arguments())
                    .bind("workflowRunId", newTask.workflowRunId())
                    .bind("activityRunId", newTask.activityRunId())
                    .bind("activityName", newTask.activityName())
                    .bind("activityInvocationId", newTask.activityInvocationId())
                    .bind("invokingTaskId", newTask.invokingTaskId())
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .mapTo(UUID.class)
                .list();
    }

    public List<UUID> updateAllTasks(final Collection<WorkflowTaskRowUpdate> taskUpdates) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                WITH "CTE_TASK" AS (
                    SELECT "ID"
                      FROM "WORKFLOW_TASK"
                     WHERE "ID" = :id
                       FOR UPDATE
                      SKIP LOCKED
                     LIMIT 1)
                UPDATE "WORKFLOW_TASK"
                   SET "STATUS" = :status
                     , "SCHEDULED_FOR" = :scheduledFor
                     , "UPDATED_AT" = NOW()
                     , "ENDED_AT" = :endedAt
                  FROM "CTE_TASK"
                 WHERE "WORKFLOW_TASK"."ID" = "CTE_TASK"."ID"
                RETURNING "WORKFLOW_TASK"."ID"
                """);

        for (final WorkflowTaskRowUpdate taskUpdate : taskUpdates) {
            preparedBatch
                    .bindMethods(taskUpdate)
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .mapTo(UUID.class)
                .list();
    }

    public Optional<PolledWorkflowTaskRow> pollTask(final String queue) {
        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE_POLL" AS (
                    SELECT "ID"
                         , "STATUS"
                         , "WORKFLOW_RUN_ID"
                      FROM "WORKFLOW_TASK"
                     WHERE "QUEUE" = :queue
                       AND "STATUS" = ANY(CAST('{PENDING, PENDING_RETRY, PENDING_RESUME}' AS WORKFLOW_TASK_STATUS[]))
                       AND "SCHEDULED_FOR" <= NOW()
                     ORDER BY "PRIORITY" DESC NULLS LAST
                            , "SCHEDULED_FOR"
                            , "CREATED_AT"
                       FOR UPDATE
                      SKIP LOCKED
                     LIMIT 1)
                UPDATE "WORKFLOW_TASK"
                   SET "STATUS" = 'RUNNING'
                     , "UPDATED_AT" = NOW()
                     , "STARTED_AT" = NOW()
                     , "ATTEMPT" = CASE WHEN "WORKFLOW_TASK"."STATUS" = 'PENDING_RESUME'
                                        THEN "WORKFLOW_TASK"."ATTEMPT"
                                        ELSE COALESCE("WORKFLOW_TASK"."ATTEMPT", 0) + 1
                                     END
                  FROM "CTE_POLL"
                 INNER JOIN "WORKFLOW_RUN"
                    ON "WORKFLOW_RUN"."ID" = "CTE_POLL"."WORKFLOW_RUN_ID"
                 WHERE "WORKFLOW_TASK"."ID" = "CTE_POLL"."ID"
                RETURNING "WORKFLOW_TASK"."ID"
                        , "WORKFLOW_TASK"."QUEUE"
                        , "WORKFLOW_TASK"."PRIORITY"
                        , "WORKFLOW_TASK"."STATUS"
                        , "CTE_POLL"."STATUS" AS "PREVIOUS_STATUS"
                        , "WORKFLOW_RUN"."WORKFLOW_NAME"
                        , "WORKFLOW_RUN"."WORKFLOW_VERSION"
                        , "WORKFLOW_TASK"."WORKFLOW_RUN_ID"
                        , "WORKFLOW_TASK"."ACTIVITY_RUN_ID"
                        , "WORKFLOW_TASK"."ACTIVITY_NAME"
                        , "WORKFLOW_TASK"."ACTIVITY_INVOCATION_ID"
                        , "WORKFLOW_TASK"."INVOKING_TASK_ID"
                        , "WORKFLOW_TASK"."ARGUMENTS"
                        , "WORKFLOW_TASK"."ATTEMPT"
                        , "WORKFLOW_TASK"."STARTED_AT"
                """);

        return update
                .bind("queue", queue)
                .executeAndReturnGeneratedKeys("*")
                .map(polledWorkflowTaskRowMapper)
                .findOne();
    }

    public List<WorkflowTaskRow> getQueuedTasksById(final Collection<UUID> taskIds) {
        final Query query = jdbiHandle.createQuery("""
                SELECT *
                  FROM "WORKFLOW_TASK"
                 WHERE "ID" = ANY(:taskIds)
                """);

        return query
                .bindArray("taskIds", UUID.class, taskIds)
                .map(queuedWorkflowTaskRowMapper)
                .list();
    }

    public List<WorkflowScheduleRow> createAllSchedules(final Collection<NewWorkflowScheduleRow> newSchedules) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_SCHEDULE" (
                  "NAME"
                , "CRON"
                , "WORKFLOW_NAME"
                , "WORKFLOW_VERSION"
                , "PRIORITY"
                , "UNIQUE_KEY"
                , "ARGUMENTS"
                , "CREATED_AT"
                , "NEXT_TRIGGER"
                ) VALUES (
                  :name
                , :cron
                , :workflowName
                , :workflowVersion
                , :priority
                , :uniqueKey
                , :arguments
                , NOW()
                , :nextTrigger
                )
                RETURNING *
                """);

        for (final NewWorkflowScheduleRow newSchedule : newSchedules) {
            preparedBatch
                    .bindMethods(newSchedule)
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .map(ConstructorMapper.of(WorkflowScheduleRow.class))
                .list();
    }

    public WorkflowScheduleRow createSchedule(final NewWorkflowScheduleRow newSchedule) {
        final List<WorkflowScheduleRow> createdSchedules = createAllSchedules(List.of(newSchedule));
        if (!createdSchedules.isEmpty()) {
            return createdSchedules.getFirst();
        }

        return null;
    }

    public List<WorkflowScheduleRow> updateAllScheduleTriggers(
            final Collection<WorkflowScheduleRowTriggerUpdate> triggerUpdates) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                UPDATE "WORKFLOW_SCHEDULE"
                   SET "LAST_TRIGGER" = NOW()
                     , "NEXT_TRIGGER" = :nextTrigger
                     , "UPDATED_AT" = NOW()
                 WHERE "ID" = :scheduleId
                RETURNING *
                """);

        for (final WorkflowScheduleRowTriggerUpdate triggerUpdate : triggerUpdates) {
            preparedBatch
                    .bindMethods(triggerUpdate)
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .map(ConstructorMapper.of(WorkflowScheduleRow.class))
                .list();
    }

    public List<WorkflowScheduleRow> getAllDueSchedules() {
        final Query query = jdbiHandle.createQuery("""
                SELECT *
                  FROM "WORKFLOW_SCHEDULE"
                 WHERE "NEXT_TRIGGER" <= NOW()
                   FOR UPDATE
                """);

        return query
                .map(ConstructorMapper.of(WorkflowScheduleRow.class))
                .list();
    }

}
