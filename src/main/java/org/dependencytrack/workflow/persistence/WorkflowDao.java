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
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.workflow.persistence.mapping.WorkflowEventArgumentFactory;
import org.dependencytrack.workflow.persistence.mapping.WorkflowPayloadArgumentFactory;
import org.dependencytrack.workflow.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventInboxRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventLogRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.PolledActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowEventInboxRow;
import org.dependencytrack.workflow.persistence.model.WorkflowEventLogRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRowUpdate;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;

import java.time.Duration;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class WorkflowDao {

    private final Handle jdbiHandle;

    public WorkflowDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public WorkflowRunRow createWorkflowRun(final NewWorkflowRunRow newWorkflowRun) {
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "WORKFLOW_RUN" (
                  "ID"
                , "WORKFLOW_NAME"
                , "WORKFLOW_VERSION"
                , "STATUS"
                , "ARGUMENT"
                , "CREATED_AT"
                ) VALUES (
                  :id
                , :workflowName
                , :workflowVersion
                , 'WORKFLOW_RUN_STATUS_PENDING'
                , :argument
                , NOW()
                )
                """);

        return update
                .bindMethods(newWorkflowRun)
                .registerArgument(new WorkflowPayloadArgumentFactory())
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .executeAndReturnGeneratedKeys("*")
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .findOne()
                .orElse(null);
    }

    public List<WorkflowRunRow> createWorkflowRuns(final Collection<NewWorkflowRunRow> newWorkflowRuns) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_RUN" (
                  "ID"
                , "WORKFLOW_NAME"
                , "WORKFLOW_VERSION"
                , "STATUS"
                , "ARGUMENT"
                , "CREATED_AT"
                ) VALUES (
                  :id
                , :workflowName
                , :workflowVersion
                , 'WORKFLOW_RUN_STATUS_PENDING'
                , :argument
                , NOW()
                )
                RETURNING *
                """);

        for (final NewWorkflowRunRow newWorkflowRun : newWorkflowRuns) {
            preparedBatch
                    .bindMethods(newWorkflowRun)
                    .add();
        }

        return preparedBatch
                .registerArgument(new WorkflowPayloadArgumentFactory())
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .executePreparedBatch("*")
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .list();
    }

    public WorkflowRunRow updateWorkflowRun(
            final UUID workerInstanceId,
            final WorkflowRunRowUpdate runUpdate) {
        final Update update = jdbiHandle.createUpdate("""
                UPDATE "WORKFLOW_RUN"
                   SET "STATUS" = COALESCE(:status, "STATUS")
                     , "ARGUMENT" = COALESCE(:argument, "ARGUMENT")
                     , "RESULT" = COALESCE(:result, "RESULT")
                     , "FAILURE_DETAILS" = COALESCE(:failureDetails, "FAILURE_DETAILS")
                     , "LOCKED_BY" = NULL
                     , "LOCKED_UNTIL" = NULL
                     , "CREATED_AT" = COALESCE(:createdAt, "CREATED_AT")
                     , "UPDATED_AT" = COALESCE(:updatedAt, "UPDATED_AT")
                     , "COMPLETED_AT" = COALESCE(:completedAt, "COMPLETED_AT")
                 WHERE "ID" = :id
                   AND "LOCKED_BY" = :workerInstanceId
                RETURNING *
                """);

        return update
                .registerArgument(new WorkflowPayloadArgumentFactory())
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindMethods(runUpdate)
                .executeAndReturnGeneratedKeys("*")
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .findOne()
                .orElse(null);
    }

    public Map<UUID, PolledWorkflowRunRow> pollAndLockWorkflowRuns(
            final UUID workerInstanceId,
            final String workflowName,
            final Duration lockTimeout,
            final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE_POLL" AS (
                    SELECT "ID"
                      FROM "WORKFLOW_RUN"
                     WHERE "WORKFLOW_NAME" = :workflowName
                       AND ("LOCKED_UNTIL" IS NULL OR "LOCKED_UNTIL" <= NOW())
                       AND EXISTS (SELECT 1
                                     FROM "WORKFLOW_EVENT_INBOX"
                                    WHERE "WORKFLOW_RUN_ID" = "WORKFLOW_RUN"."ID"
                                      AND ("VISIBLE_FROM" IS NULL OR "VISIBLE_FROM" <= NOW()))
                     ORDER BY "PRIORITY" DESC NULLS LAST
                            , "CREATED_AT"
                       FOR UPDATE
                      SKIP LOCKED
                     LIMIT :limit)
                UPDATE "WORKFLOW_RUN"
                   SET "LOCKED_BY" = :workerInstanceId
                     , "LOCKED_UNTIL" = NOW() + :lockTimeout
                  FROM "CTE_POLL"
                 WHERE "CTE_POLL"."ID" = "WORKFLOW_RUN"."ID"
                RETURNING "WORKFLOW_RUN"."ID"
                        , "WORKFLOW_RUN"."WORKFLOW_NAME"
                        , "WORKFLOW_RUN"."WORKFLOW_VERSION"
                        , "WORKFLOW_RUN"."PRIORITY"
                        , "WORKFLOW_RUN"."ARGUMENT"
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowName", workflowName)
                .bind("lockTimeout", lockTimeout)
                .bind("limit", limit)
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .executeAndReturnGeneratedKeys(
                        "ID",
                        "WORKFLOW_NAME",
                        "WORKFLOW_VERSION",
                        "PRIORITY",
                        "ARGUMENT")
                .map(ConstructorMapper.of(PolledWorkflowRunRow.class))
                .collectToMap(PolledWorkflowRunRow::id, Function.identity());
    }

    public int unlockWorkflowRun(final UUID workerInstanceId, final UUID workflowRunId) {
        final Update update = jdbiHandle.createUpdate("""
                UPDATE "WORKFLOW_RUN"
                   SET "LOCKED_BY" = NULL
                     , "LOCKED_UNTIL" = NULL
                 WHERE "ID" = :workflowRunId
                   AND "LOCKED_BY" = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId)
                .bind("workflowRunId", workflowRunId)
                .execute();
    }

    public int createInboxEvents(final SequencedCollection<NewWorkflowEventInboxRow> newEvents) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_EVENT_INBOX" (
                  "WORKFLOW_RUN_ID"
                , "TIMESTAMP"
                , "VISIBLE_FROM"
                , "EVENT"
                ) VALUES (
                  :workflowRunId
                , NOW()
                , :visibleFrom
                , :event
                )
                RETURNING "ID"
                """);

        for (final NewWorkflowEventInboxRow newEvent : newEvents) {
            preparedBatch
                    .bindMethods(newEvent)
                    .add();
        }

        final List<Long> ids = preparedBatch
                .registerArgument(new WorkflowEventArgumentFactory())
                .executePreparedBatch("ID")
                .mapTo(Long.class)
                .list();
        return ids.size();
    }

    public Map<UUID, List<WorkflowEvent>> pollAndLockInboxEvents(
            final UUID workerInstanceId,
            final Collection<UUID> workflowRunIds) {
        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE" AS (
                    SELECT "ID"
                      FROM "WORKFLOW_EVENT_INBOX"
                     WHERE "WORKFLOW_RUN_ID" = ANY(:workflowRunIds)
                       AND ("VISIBLE_FROM" IS NULL OR "VISIBLE_FROM" <= NOW())
                     ORDER BY "ID")
                UPDATE "WORKFLOW_EVENT_INBOX"
                   SET "LOCKED_BY" = :workerInstanceId
                  FROM "CTE"
                 WHERE "CTE"."ID" = "WORKFLOW_EVENT_INBOX"."ID"
                RETURNING "WORKFLOW_EVENT_INBOX".*
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .registerColumnMapper(WorkflowEvent.class, new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .executeAndReturnGeneratedKeys("*")
                .map(ConstructorMapper.of(WorkflowEventInboxRow.class))
                .stream()
                .collect(Collectors.groupingBy(
                        WorkflowEventInboxRow::workflowRunId,
                        Collectors.mapping(WorkflowEventInboxRow::event, Collectors.toList())));
    }

    public int unlockInboxEvents(final UUID workerInstanceId, final UUID workflowRunId) {
        final Update update = jdbiHandle.createUpdate("""
                UPDATE "WORKFLOW_EVENT_INBOX"
                   SET "LOCKED_BY" = NULL
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                   AND "LOCKED_BY" = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId)
                .bind("workflowRunId", workflowRunId)
                .execute();
    }

    public int deleteLockedInboxEvents(final UUID workerInstanceId, final UUID workflowRunId) {
        final Update update = jdbiHandle.createUpdate("""
                DELETE
                  FROM "WORKFLOW_EVENT_INBOX"
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                   AND "LOCKED_BY" = :workerInstanceId
                """);

        return update
                .bind("workflowRunId", workflowRunId)
                .bind("workerInstanceId", workerInstanceId.toString())
                .execute();
    }

    public void createWorkflowEventLogEntries(final Collection<NewWorkflowEventLogRow> newEventLogEntries) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_EVENT_LOG" (
                  "WORKFLOW_RUN_ID"
                , "SEQUENCE_ID"
                , "TIMESTAMP"
                , "EVENT"
                ) VALUES (
                  :workflowRunId
                , :sequenceId
                , :timestamp
                , :event
                )
                """);

        for (final NewWorkflowEventLogRow newLogEntry : newEventLogEntries) {
            preparedBatch
                    .bindMethods(newLogEntry)
                    .add();
        }

        preparedBatch
                .registerArgument(new WorkflowEventArgumentFactory())
                .executeAndGetModCount();
    }

    public List<WorkflowEvent> getWorkflowRunEventLog(final UUID workflowRunId) {
        final Query query = jdbiHandle.createQuery("""
                SELECT "EVENT"
                  FROM "WORKFLOW_EVENT_LOG"
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                 ORDER BY "TIMESTAMP"
                """);

        return query
                .bind("workflowRunId", workflowRunId)
                .map(new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .list();
    }

    public Map<UUID, List<WorkflowEvent>> getWorkflowEventLogs(final Collection<UUID> workflowRunIds) {
        final Query query = jdbiHandle.createQuery("""
                SELECT *
                  FROM "WORKFLOW_EVENT_LOG"
                 WHERE "WORKFLOW_RUN_ID" = ANY(:workflowRunIds)
                 ORDER BY "SEQUENCE_ID"
                """);

        return query
                .registerColumnMapper(WorkflowEvent.class, new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .map(ConstructorMapper.of(WorkflowEventLogRow.class))
                .stream()
                .collect(Collectors.groupingBy(
                        WorkflowEventLogRow::workflowRunId,
                        Collectors.mapping(WorkflowEventLogRow::event, Collectors.toList())));
    }

    public int createActivityTasks(final Collection<NewActivityTaskRow> newTasks) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_ACTIVITY_TASK" (
                  "WORKFLOW_RUN_ID"
                , "SEQUENCE_ID"
                , "ACTIVITY_NAME"
                , "PRIORITY"
                , "ARGUMENT"
                , "CREATED_AT"
                ) VALUES (
                  :workflowRunId
                , :sequenceId
                , :activityName
                , :priority
                , :argument
                , NOW()
                )
                """);

        for (final NewActivityTaskRow newTask : newTasks) {
            preparedBatch
                    .bindMethods(newTask)
                    .add();
        }

        final Iterator<Integer> modCountIterator = preparedBatch
                .registerArgument(new WorkflowPayloadArgumentFactory())
                .executeAndGetModCount();
        int modCount = 0;
        while (modCountIterator.hasNext()) {
            modCount += modCountIterator.next();
        }

        return modCount;
    }

    public List<PolledActivityTaskRow> pollAndLockActivityTasks(
            final UUID workerInstanceId,
            final String activityName,
            final Duration lockTimeout,
            final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE_POLL" AS (
                    SELECT "ID"
                      FROM "WORKFLOW_ACTIVITY_TASK"
                     WHERE "ACTIVITY_NAME" = :activityName
                       AND ("LOCKED_UNTIL" IS NULL OR "LOCKED_UNTIL" <= NOW())
                     ORDER BY "PRIORITY" DESC NULLS LAST
                            , "CREATED_AT"
                       FOR UPDATE
                      SKIP LOCKED
                     LIMIT :limit)
                UPDATE "WORKFLOW_ACTIVITY_TASK"
                   SET "ATTEMPT" = COALESCE("WORKFLOW_TASK"."ATTEMPT", 0) + 1
                     , "LOCKED_BY" = :workerInstanceId
                     , "LOCKED_UNTIL" = NOW() + :lockTimeout
                     , "UPDATED_AT" = NOW()
                  FROM "CTE_POLL"
                RETURNING "WORKFLOW_ACTIVITY_TASK"."WORKFLOW_RUN_ID"
                        , "WORKFLOW_ACTIVITY_TASK"."SEQUENCE_ID"
                        , "WORKFLOW_ACTIVITY_TASK"."ACTIVITY_NAME"
                        , "WORKFLOW_ACTIVITY_TASK"."PRIORITY"
                        , "WORKFLOW_ACTIVITY_TASK"."ARGUMENT"
                        , "WORKFLOW_ACTIVITY_TASK"."ATTEMPT"
                """);

        return update
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("activityName", activityName)
                .bind("lockTimeout", lockTimeout)
                .bind("limit", limit)
                .executeAndReturnGeneratedKeys(
                        "WORKFLOW_RUN_ID",
                        "SEQUENCE_ID",
                        "ACTIVITY_NAME",
                        "PRIORITY",
                        "ARGUMENT",
                        "ATTEMPT")
                .map(ConstructorMapper.of(PolledActivityTaskRow.class))
                .list();
    }

}
