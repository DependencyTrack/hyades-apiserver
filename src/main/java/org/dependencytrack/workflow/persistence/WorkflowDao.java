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

import org.dependencytrack.persistence.jdbi.ApiRequestConfig;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.workflow.persistence.mapping.WorkflowEventArgumentFactory;
import org.dependencytrack.workflow.persistence.mapping.WorkflowPayloadArgumentFactory;
import org.dependencytrack.workflow.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventInboxRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowEventLogRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.PolledActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.PolledInboxEvent;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowEventInboxRow;
import org.dependencytrack.workflow.persistence.model.WorkflowEventLogRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunListRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRowUpdate;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.result.ResultIterator;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class WorkflowDao {

    private final Handle jdbiHandle;

    public WorkflowDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
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
                , 'PENDING'
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

    public List<WorkflowRunListRow> getWorkflowRuns() {
        // TODO: Make apiFilterParameter work with ID, without risking type errors
        //  in case the provided value is not a valid UUID.
        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="apiFilterParameter" type="String" -->
                <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
                <#-- @ftlvariable name="apiOrderByClause" type="String" -->
                SELECT "ID" AS "id"
                     , "WORKFLOW_NAME" AS "workflowName"
                     , "WORKFLOW_VERSION" AS "workflowVersion"
                     , "STATUS" AS "status"
                     , "CUSTOM_STATUS" AS "customStatus"
                     , "PRIORITY" AS "priority"
                     , "CREATED_AT" AS "createdAt"
                     , "UPDATED_AT" AS "updatedAt"
                     , "COMPLETED_AT" AS "completedAt"
                     , (SELECT COUNT(*)
                          FROM "WORKFLOW_EVENT_LOG" AS "WEL"
                         WHERE "WEL"."WORKFLOW_RUN_ID" = "WORKFLOW_RUN"."ID") AS "historySize"
                     , (SELECT COUNT(*)
                          FROM "WORKFLOW_EVENT_INBOX" AS "WEI"
                         WHERE "WEI"."WORKFLOW_RUN_ID" = "WORKFLOW_RUN"."ID") AS "pendingEvents"
                     , (SELECT COUNT(*)
                          FROM "WORKFLOW_ACTIVITY_TASK" AS "WAT"
                         WHERE "WAT"."WORKFLOW_RUN_ID" = "WORKFLOW_RUN"."ID") AS "pendingActivities"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "WORKFLOW_RUN"
                <#if apiFilterParameter??>
                 WHERE "WORKFLOW_NAME" LIKE ('%' || ${apiFilterParameter} || '%')
                </#if>
                ${apiOrderByClause!}
                ${apiOffsetLimitClause!}
                """);

        return query
                .configure(ApiRequestConfig.class, apiRequestConfig ->
                        apiRequestConfig.setOrderingAllowedColumns(Set.of(
                                new ApiRequestConfig.OrderingColumn("id"),
                                new ApiRequestConfig.OrderingColumn("workflowName"),
                                new ApiRequestConfig.OrderingColumn("priority"),
                                new ApiRequestConfig.OrderingColumn("createdAt"),
                                new ApiRequestConfig.OrderingColumn("updatedAt"),
                                new ApiRequestConfig.OrderingColumn("completedAt"),
                                new ApiRequestConfig.OrderingColumn("historySize"),
                                new ApiRequestConfig.OrderingColumn("pendingEvents"),
                                new ApiRequestConfig.OrderingColumn("pendingActivities"))))
                .map(ConstructorMapper.of(WorkflowRunListRow.class))
                .list();
    }

    public int updateWorkflowRuns(
            final UUID workerInstanceId,
            final Collection<WorkflowRunRowUpdate> runUpdates) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                UPDATE "WORKFLOW_RUN"
                   SET "STATUS" = COALESCE(:status, "STATUS")
                     , "CUSTOM_STATUS" = COALESCE(:customStatus, "CUSTOM_STATUS")
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
                """);

        for (final WorkflowRunRowUpdate runUpdate : runUpdates) {
            preparedBatch
                    .bind("workerInstanceId", workerInstanceId.toString())
                    .bindMethods(runUpdate)
                    .add();
        }

        final ResultIterator<Integer> modCountIterator = preparedBatch
                .registerArgument(new WorkflowPayloadArgumentFactory())
                .executeAndGetModCount();

        int modCount = 0;
        while (modCountIterator.hasNext()) {
            modCount += modCountIterator.next();
        }

        return modCount;
    }

    public WorkflowRunRow getWorkflowRun(final UUID id) {
        final Query query = jdbiHandle.createQuery("""
                SELECT *
                  FROM "WORKFLOW_RUN"
                 WHERE "ID" = :id
                """);

        return query
                .bind("id", id)
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .findOne()
                .orElse(null);
    }

    public boolean existsWorkflowRunWithNonTerminalStatus(final UUID id) {
        final Query query = jdbiHandle.createQuery("""
                SELECT EXISTS (
                    SELECT 1
                      FROM "WORKFLOW_RUN"
                     WHERE "ID" = :id
                       AND "STATUS" = ANY('{PENDING, RUNNING, SUSPENDED}'::WORKFLOW_RUN_STATUS[]))
                """);

        return query
                .bind("id", id)
                .mapTo(Boolean.class)
                .findOne()
                .orElse(false);
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
                       AND "STATUS" = ANY('{PENDING, RUNNING, SUSPENDED}'::WORKFLOW_RUN_STATUS[])
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
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowRunId", workflowRunId)
                .execute();
    }

    public int createInboxEvents(final SequencedCollection<NewWorkflowEventInboxRow> newEvents) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_EVENT_INBOX" (
                  "WORKFLOW_RUN_ID"
                , "VISIBLE_FROM"
                , "EVENT"
                ) VALUES (
                  :workflowRunId
                , :visibleFrom
                , :event
                )
                RETURNING 1
                """);

        for (final NewWorkflowEventInboxRow newEvent : newEvents) {
            preparedBatch
                    .bindMethods(newEvent)
                    .add();
        }

        return preparedBatch
                .registerArgument(new WorkflowEventArgumentFactory())
                .executePreparedBatch("1")
                .mapTo(Integer.class)
                .stream()
                .mapToInt(Integer::intValue)
                .sum();
    }

    public Map<UUID, List<PolledInboxEvent>> pollAndLockInboxEvents(
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
                     , "DEQUEUE_COUNT" = COALESCE("DEQUEUE_COUNT", 0) + 1
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
                        Collectors.mapping(
                                row -> new PolledInboxEvent(row.event(), row.dequeueCount()),
                                Collectors.toList())));
    }

    public List<WorkflowEvent> getInboxEvents(final UUID workflowRunId) {
        final Query query = jdbiHandle.createQuery("""
                SELECT "EVENT"
                  FROM "WORKFLOW_EVENT_INBOX"
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                 ORDER BY "ID"
                """);

        return query
                .bind("workflowRunId", workflowRunId)
                .map(new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .list();
    }

    public int unlockInboxEvents(final UUID workerInstanceId, final UUID workflowRunId, final Duration visibilityDelay) {
        final Update update = jdbiHandle.createUpdate("""
                UPDATE "WORKFLOW_EVENT_INBOX"
                   SET "LOCKED_BY" = NULL
                     , "VISIBLE_FROM" = NOW() + :visibilityDelay
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                   AND "LOCKED_BY" = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowRunId", workflowRunId)
                .bind("visibilityDelay", visibilityDelay)
                .execute();
    }

    public int deleteLockedInboxEvents(final UUID workerInstanceId, final Collection<UUID> workflowRunIds) {
        final Update update = jdbiHandle.createUpdate("""
                DELETE
                  FROM "WORKFLOW_EVENT_INBOX"
                 WHERE "WORKFLOW_RUN_ID" = ANY(:workflowRunIds)
                   AND "LOCKED_BY" = :workerInstanceId
                """);

        return update
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bind("workerInstanceId", workerInstanceId.toString())
                .execute();
    }

    public void createWorkflowEventLogEntries(final Collection<NewWorkflowEventLogRow> newEventLogEntries) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_EVENT_LOG" (
                  "WORKFLOW_RUN_ID"
                , "SEQUENCE_NUMBER"
                , "EVENT"
                ) VALUES (
                  :workflowRunId
                , :sequenceNumber
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
                 ORDER BY "SEQUENCE_NUMBER"
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
                 ORDER BY "SEQUENCE_NUMBER"
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
                , "SCHEDULED_EVENT_ID"
                , "ACTIVITY_NAME"
                , "PRIORITY"
                , "ARGUMENT"
                , "VISIBLE_FROM"
                , "CREATED_AT"
                ) VALUES (
                  :workflowRunId
                , :scheduledEventId
                , :activityName
                , :priority
                , :argument
                , :visibleFrom
                , NOW()
                )
                RETURNING 1
                """);

        for (final NewActivityTaskRow newTask : newTasks) {
            preparedBatch
                    .bindMethods(newTask)
                    .add();
        }

        return preparedBatch
                .registerArgument(new WorkflowPayloadArgumentFactory())
                .executePreparedBatch("1")
                .mapTo(Integer.class)
                .stream()
                .mapToInt(Integer::intValue)
                .sum();
    }

    public List<PolledActivityTaskRow> pollAndLockActivityTasks(
            final UUID workerInstanceId,
            final String activityName,
            final Duration lockTimeout,
            final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE_POLL" AS (
                    SELECT "WORKFLOW_RUN_ID"
                         , "SCHEDULED_EVENT_ID"
                      FROM "WORKFLOW_ACTIVITY_TASK"
                     WHERE "ACTIVITY_NAME" = :activityName
                       AND ("VISIBLE_FROM" IS NULL OR "VISIBLE_FROM" <= NOW())
                       AND ("LOCKED_UNTIL" IS NULL OR "LOCKED_UNTIL" <= NOW())
                     ORDER BY "PRIORITY" DESC NULLS LAST
                            , "CREATED_AT"
                       FOR UPDATE
                      SKIP LOCKED
                     LIMIT :limit)
                UPDATE "WORKFLOW_ACTIVITY_TASK"
                   SET "LOCKED_BY" = :workerInstanceId
                     , "LOCKED_UNTIL" = NOW() + :lockTimeout
                     , "UPDATED_AT" = NOW()
                  FROM "CTE_POLL"
                 WHERE "CTE_POLL"."WORKFLOW_RUN_ID" = "WORKFLOW_ACTIVITY_TASK"."WORKFLOW_RUN_ID"
                   AND "CTE_POLL"."SCHEDULED_EVENT_ID" = "WORKFLOW_ACTIVITY_TASK"."SCHEDULED_EVENT_ID"
                RETURNING "WORKFLOW_ACTIVITY_TASK"."WORKFLOW_RUN_ID"
                        , "WORKFLOW_ACTIVITY_TASK"."SCHEDULED_EVENT_ID"
                        , "WORKFLOW_ACTIVITY_TASK"."ACTIVITY_NAME"
                        , "WORKFLOW_ACTIVITY_TASK"."PRIORITY"
                        , "WORKFLOW_ACTIVITY_TASK"."ARGUMENT"
                        , "WORKFLOW_ACTIVITY_TASK"."LOCKED_UNTIL"
                """);

        return update
                .registerColumnMapper(WorkflowPayload.class, new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("activityName", activityName)
                .bind("lockTimeout", lockTimeout)
                .bind("limit", limit)
                .executeAndReturnGeneratedKeys(
                        "WORKFLOW_RUN_ID",
                        "SCHEDULED_EVENT_ID",
                        "ACTIVITY_NAME",
                        "PRIORITY",
                        "ARGUMENT",
                        "LOCKED_UNTIL")
                .map(ConstructorMapper.of(PolledActivityTaskRow.class))
                .list();
    }

    public Instant extendActivityTaskLock(
            final UUID workerInstanceId,
            final ActivityTaskId activityTask,
            final Duration lockTimeout) {
        final Update update = jdbiHandle.createUpdate("""
                UPDATE "WORKFLOW_ACTIVITY_TASK"
                   SET "LOCKED_UNTIL" = "LOCKED_UNTIL" + :lockTimeout
                     , "UPDATED_AT" = NOW()
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                   AND "SCHEDULED_EVENT_ID" = :scheduledEventId
                   AND "LOCKED_BY" = :workerInstanceId
                RETURNING "LOCKED_UNTIL"
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowRunId", activityTask.workflowRunId())
                .bind("scheduledEventId", activityTask.scheduledEventId())
                .bind("lockTimeout", lockTimeout)
                .executeAndReturnGeneratedKeys("LOCKED_UNTIL")
                .mapTo(Instant.class)
                .findOne()
                .orElse(null);
    }

    public int unlockActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var workflowRunIds = new ArrayList<UUID>(activityTasks.size());
        final var scheduledEventIds = new ArrayList<Integer>(activityTasks.size());

        for (final ActivityTaskId activityTask : activityTasks) {
            workflowRunIds.add(activityTask.workflowRunId());
            scheduledEventIds.add(activityTask.scheduledEventId());
        }

        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE" AS (
                    SELECT *
                      FROM UNNEST(:workflowRunIds, :scheduledEventIds) AS t("WORKFLOW_RUN_ID", "SCHEDULED_EVENT_ID"))
                UPDATE "WORKFLOW_ACTIVITY_TASK"
                   SET "LOCKED_BY" = NULL
                     , "LOCKED_UNTIL" = NULL
                  FROM "CTE"
                 WHERE "CTE"."WOKFLOW_RUN_ID" = "WORKFLOW_ACTIVITY_TASK"."WORKFLOW_RUN_ID"
                   AND "CTE"."SCHEDULED_EVENT_ID" = "WORKFLOW_ACTIVITY_TASK"."SCHEDULED_EVENT_ID"
                   AND "WORKFLOW_ACTIVITY_TASK"."LOCKED_BY" = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bindArray("scheduledEventIds", Integer.class, scheduledEventIds)
                .execute();
    }

    public int deleteLockedActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var workflowRunIds = new ArrayList<UUID>(activityTasks.size());
        final var scheduledEventIds = new ArrayList<Integer>(activityTasks.size());

        for (final ActivityTaskId activityTask : activityTasks) {
            workflowRunIds.add(activityTask.workflowRunId());
            scheduledEventIds.add(activityTask.scheduledEventId());
        }

        final Update update = jdbiHandle.createUpdate("""
                WITH "CTE" AS (
                    SELECT *
                      FROM UNNEST(:workflowRunIds, :scheduledEventIds) AS t("WORKFLOW_RUN_ID", "SCHEDULED_EVENT_ID"))
                DELETE
                  FROM "WORKFLOW_ACTIVITY_TASK"
                 USING "CTE"
                 WHERE "CTE"."WORKFLOW_RUN_ID" = "WORKFLOW_ACTIVITY_TASK"."WORKFLOW_RUN_ID"
                   AND "CTE"."SCHEDULED_EVENT_ID" = "WORKFLOW_ACTIVITY_TASK"."SCHEDULED_EVENT_ID"
                   AND "WORKFLOW_ACTIVITY_TASK"."LOCKED_BY" = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bindArray("scheduledEventIds", Integer.class, scheduledEventIds)
                .execute();
    }

}
