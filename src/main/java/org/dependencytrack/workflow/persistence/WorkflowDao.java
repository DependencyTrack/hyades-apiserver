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
import org.dependencytrack.workflow.WorkflowRunStatus;
import org.dependencytrack.workflow.persistence.mapping.PolledActivityTaskRowMapper;
import org.dependencytrack.workflow.persistence.mapping.PolledWorkflowEventRowMapper;
import org.dependencytrack.workflow.persistence.mapping.PolledWorkflowRunRowMapper;
import org.dependencytrack.workflow.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.workflow.persistence.mapping.WorkflowEventArgumentFactory;
import org.dependencytrack.workflow.persistence.mapping.WorkflowEventSqlArrayType;
import org.dependencytrack.workflow.persistence.mapping.WorkflowPayloadSqlArrayType;
import org.dependencytrack.workflow.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.persistence.model.DeleteInboxEventsCommand;
import org.dependencytrack.workflow.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunInboxRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunJournalRow;
import org.dependencytrack.workflow.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.PolledActivityTaskRow;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowEventRow;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowConcurrencyGroupRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunListRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRowUpdate;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;

import jakarta.json.Json;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

public final class WorkflowDao {

    private final Handle jdbiHandle;

    public WorkflowDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public List<UUID> createRuns(final Collection<NewWorkflowRunRow> newRuns) {
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "WORKFLOW_RUN" (
                  "ID"
                , "PARENT_ID"
                , "WORKFLOW_NAME"
                , "WORKFLOW_VERSION"
                , "CONCURRENCY_GROUP_ID"
                , "PRIORITY"
                , "TAGS"
                )
                SELECT "ID"
                     , "PARENT_ID"
                     , "WORKFLOW_NAME"
                     , "WORKFLOW_VERSION"
                     , "CONCURRENCY_GROUP_ID"
                     , "PRIORITY"
                     , (SELECT ARRAY_AGG("TAG")
                          FROM JSON_ARRAY_ELEMENTS_TEXT("TAGS") AS "TAG") AS "TAGS"
                  FROM UNNEST (
                         :ids
                       , :parentIds
                       , :workflowNames
                       , :workflowVersions
                       , :concurrencyGroupIds
                       , :priorities
                       , CAST(:tagsJsons AS JSON[])
                       ) AS "NEW_RUN" (
                         "ID"
                       , "PARENT_ID"
                       , "WORKFLOW_NAME"
                       , "WORKFLOW_VERSION"
                       , "CONCURRENCY_GROUP_ID"
                       , "PRIORITY"
                       , "TAGS")
                RETURNING "ID"
                """);

        final var ids = new ArrayList<UUID>(newRuns.size());
        final var parentIds = new ArrayList<UUID>(newRuns.size());
        final var workflowNames = new ArrayList<String>(newRuns.size());
        final var workflowVersions = new ArrayList<Integer>(newRuns.size());
        final var concurrencyGroupIds = new ArrayList<String>(newRuns.size());
        final var priorities = new ArrayList<Integer>(newRuns.size());
        final var tagsJsons = new ArrayList<String>(newRuns.size());

        for (final NewWorkflowRunRow newRun : newRuns) {
            // Workaround for JDBC getting confused with nested arrays.
            // Transmit tags as JSON array instead, and convert it to
            // a native TEXT[] array before inserting it.
            final String tagsJson;
            if (newRun.tags() == null || newRun.tags().isEmpty()) {
                tagsJson = null;
            } else {
                final var tagsJsonArray = Json.createArrayBuilder();
                newRun.tags().forEach(tagsJsonArray::add);
                tagsJson = tagsJsonArray.build().toString();
            }

            ids.add(newRun.id());
            parentIds.add(newRun.parentId());
            workflowNames.add(newRun.workflowName());
            workflowVersions.add(newRun.workflowVersion());
            concurrencyGroupIds.add(newRun.concurrencyGroupId());
            priorities.add(newRun.priority());
            tagsJsons.add(tagsJson);
        }

        return update
                .bindArray("ids", UUID.class, ids)
                .bindArray("parentIds", UUID.class, parentIds)
                .bindArray("workflowNames", String.class, workflowNames)
                .bindArray("workflowVersions", Integer.class, workflowVersions)
                .bindArray("concurrencyGroupIds", String.class, concurrencyGroupIds)
                .bindArray("priorities", Integer.class, priorities)
                .bindArray("tagsJsons", String.class, tagsJsons)
                .executeAndReturnGeneratedKeys("ID")
                .mapTo(UUID.class)
                .list();
    }

    public int maybeCreateConcurrencyGroups(final Collection<WorkflowConcurrencyGroupRow> concurrencyGroups) {
        // NB: We must *not* use ON CONFLICT DO UPDATE here, since we have to assume that the
        // existing NEXT_RUN_ID is already being worked on, even if it technically orders
        // *after* the run ID we're trying to insert here.
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "WORKFLOW_CONCURRENCY_GROUP" (
                  "ID"
                , "NEXT_RUN_ID"
                )
                SELECT * FROM UNNEST(:groupIds, :nextRunIds)
                ON CONFLICT ("ID") DO NOTHING
                """);

        final var groupIds = new ArrayList<String>(concurrencyGroups.size());
        final var nextRunIds = new ArrayList<UUID>(concurrencyGroups.size());
        for (final WorkflowConcurrencyGroupRow concurrencyGroup : concurrencyGroups) {
            groupIds.add(concurrencyGroup.id());
            nextRunIds.add(concurrencyGroup.nextRunId());
        }

        return update
                .bindArray("groupIds", String.class, groupIds)
                .bindArray("nextRunIds", UUID.class, nextRunIds)
                .execute();
    }

    public Map<String, String> updateConcurrencyGroups(final Collection<String> concurrencyGroupIds) {
        final Query query = jdbiHandle.createQuery("""
                WITH
                "CTE_NEXT_RUN" AS (
                    SELECT DISTINCT ON ("CONCURRENCY_GROUP_ID")
                           "CONCURRENCY_GROUP_ID"
                         , "ID"
                      FROM "WORKFLOW_RUN"
                     WHERE "CONCURRENCY_GROUP_ID" = ANY(:groupIds)
                       AND "STATUS" = ANY('{PENDING, RUNNING, SUSPENDED}'::WORKFLOW_RUN_STATUS[])
                     ORDER BY "CONCURRENCY_GROUP_ID"
                            , "PRIORITY" DESC NULLS LAST
                            , "CREATED_AT"
                ),
                "CTE_UPDATED_GROUP" AS (
                    UPDATE "WORKFLOW_CONCURRENCY_GROUP"
                       SET "NEXT_RUN_ID" = "CTE_NEXT_RUN"."ID"
                      FROM "CTE_NEXT_RUN"
                     WHERE "WORKFLOW_CONCURRENCY_GROUP"."ID" = "CTE_NEXT_RUN"."CONCURRENCY_GROUP_ID"
                    RETURNING "WORKFLOW_CONCURRENCY_GROUP"."ID"
                ),
                "CTE_DELETED_GROUP" AS (
                   DELETE
                     FROM "WORKFLOW_CONCURRENCY_GROUP"
                    WHERE "ID" = ANY(:groupIds)
                      AND "ID" != ALL(SELECT "ID" FROM "CTE_UPDATED_GROUP")
                   RETURNING "ID"
                )
                SELECT "ID"
                     , 'UPDATED' AS "STATUS"
                  FROM "CTE_UPDATED_GROUP"
                 UNION ALL
                SELECT "ID"
                     , 'DELETED' AS "STATUS"
                  FROM "CTE_DELETED_GROUP"
                """);

        return query
                .setMapKeyColumn("ID")
                .setMapValueColumn("STATUS")
                .bindArray("groupIds", String.class, concurrencyGroupIds)
                .collectInto(new GenericType<>() {
                });
    }

    public List<WorkflowRunListRow> getRunListPage(
            final String workflowNameFilter,
            final WorkflowRunStatus statusFilter,
            final String concurrencyGroupIdFilter,
            final Set<String> tagsFilter) {
        // TODO: Make apiFilterParameter work with ID, without risking type errors
        //  in case the provided value is not a valid UUID.
        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="apiFilterParameter" type="String" -->
                <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
                <#-- @ftlvariable name="apiOrderByClause" type="String" -->
                <#-- @ftlvariable name="workflowNameFilter" type="Boolean" -->
                <#-- @ftlvariable name="statusFilter" type="Boolean" -->
                <#-- @ftlvariable name="concurrencyGroupIdFilter" type="Boolean" -->
                <#-- @ftlvariable name="tagsFilter" type="Boolean" -->
                SELECT "ID" AS "id"
                     , "WORKFLOW_NAME" AS "workflowName"
                     , "WORKFLOW_VERSION" AS "workflowVersion"
                     , "STATUS" AS "status"
                     , "CUSTOM_STATUS" AS "customStatus"
                     , "CONCURRENCY_GROUP_ID" AS "concurrencyGroupId"
                     , "PRIORITY" AS "priority"
                     , "TAGS" AS "tags"
                     , "CREATED_AT" AS "createdAt"
                     , "UPDATED_AT" AS "updatedAt"
                     , "STARTED_AT" AS "startedAt"
                     , "COMPLETED_AT" AS "completedAt"
                  FROM "WORKFLOW_RUN"
                 WHERE 1 = 1
                <#if apiFilterParameter??>
                   AND "WORKFLOW_NAME" LIKE ('%' || ${apiFilterParameter} || '%')
                </#if>
                <#if workflowNameFilter>
                   AND "WORKFLOW_NAME" = :workflowNameFilter
                </#if>
                <#if statusFilter>
                   AND "STATUS" = :statusFilter
                </#if>
                <#if concurrencyGroupIdFilter>
                   AND "CONCURRENCY_GROUP_ID" = :concurrencyGroupIdFilter
                </#if>
                <#if tagsFilter>
                   AND "TAGS" @> CAST(:tagsFilter AS TEXT[])
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
                                new ApiRequestConfig.OrderingColumn("concurrencyGroupId"),
                                new ApiRequestConfig.OrderingColumn("createdAt"),
                                new ApiRequestConfig.OrderingColumn("updatedAt"),
                                new ApiRequestConfig.OrderingColumn("completedAt"))))
                .bind("workflowNameFilter", workflowNameFilter)
                .bind("statusFilter", statusFilter)
                .bind("concurrencyGroupIdFilter", concurrencyGroupIdFilter)
                .bindArray("tagsFilter", String.class, tagsFilter)
                .defineNamedBindings()
                .map(ConstructorMapper.of(WorkflowRunListRow.class))
                .list();
    }

    public List<WorkflowRunCountByNameAndStatusRow> getRunCountByNameAndStatus() {
        final Query query = jdbiHandle.createQuery("""
                SELECT "WORKFLOW_NAME"
                     , "STATUS"
                     , COUNT(*)
                  FROM "WORKFLOW_RUN"
                 GROUP BY "WORKFLOW_NAME"
                        , "STATUS";
                """);

        return query
                .map(ConstructorMapper.of(WorkflowRunCountByNameAndStatusRow.class))
                .list();
    }

    public List<UUID> updateRuns(
            final UUID workerInstanceId,
            final Collection<WorkflowRunRowUpdate> runUpdates) {
        final Update update = jdbiHandle.createUpdate("""
                UPDATE "WORKFLOW_RUN"
                   SET "STATUS" = COALESCE("RUN_UPDATE"."STATUS", "WORKFLOW_RUN"."STATUS")
                     , "CUSTOM_STATUS" = COALESCE("RUN_UPDATE"."CUSTOM_STATUS", "WORKFLOW_RUN"."CUSTOM_STATUS")
                     , "LOCKED_BY" = NULL
                     , "LOCKED_UNTIL" = NULL
                     , "CREATED_AT" = COALESCE("RUN_UPDATE"."CREATED_AT", "WORKFLOW_RUN"."CREATED_AT")
                     , "UPDATED_AT" = COALESCE("RUN_UPDATE"."UPDATED_AT", "WORKFLOW_RUN"."UPDATED_AT")
                     , "STARTED_AT" = COALESCE("RUN_UPDATE"."STARTED_AT", "WORKFLOW_RUN"."STARTED_AT")
                     , "COMPLETED_AT" = COALESCE("RUN_UPDATE"."COMPLETED_AT", "WORKFLOW_RUN"."COMPLETED_AT")
                  FROM UNNEST (
                         :ids
                       , :statuses
                       , :customStatuses
                       , :createdAts
                       , :updatedAts
                       , :startedAts
                       , :completedAts
                       ) AS "RUN_UPDATE" (
                         "ID"
                       , "STATUS"
                       , "CUSTOM_STATUS"
                       , "CREATED_AT"
                       , "UPDATED_AT"
                       , "STARTED_AT"
                       , "COMPLETED_AT")
                 WHERE "WORKFLOW_RUN"."ID" = "RUN_UPDATE"."ID"
                   AND "WORKFLOW_RUN"."LOCKED_BY" = :workerInstanceId
                RETURNING "WORKFLOW_RUN"."ID"
                """);

        final var ids = new ArrayList<UUID>(runUpdates.size());
        final var statuses = new ArrayList<WorkflowRunStatus>(runUpdates.size());
        final var customStatuses = new ArrayList<String>(runUpdates.size());
        final var createdAts = new ArrayList<Instant>(runUpdates.size());
        final var updatedAts = new ArrayList<Instant>(runUpdates.size());
        final var startedAts = new ArrayList<Instant>(runUpdates.size());
        final var completedAts = new ArrayList<Instant>(runUpdates.size());
        for (final WorkflowRunRowUpdate runUpdate : runUpdates) {
            ids.add(runUpdate.id());
            statuses.add(runUpdate.status());
            customStatuses.add(runUpdate.customStatus());
            createdAts.add(runUpdate.createdAt());
            updatedAts.add(runUpdate.updatedAt());
            startedAts.add(runUpdate.startedAt());
            completedAts.add(runUpdate.completedAt());
        }

        return update
                .registerArrayType(Instant.class, "TIMESTAMPTZ")
                .registerArrayType(WorkflowRunStatus.class, "WORKFLOW_RUN_STATUS")
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("ids", UUID.class, ids)
                .bindArray("statuses", WorkflowRunStatus.class, statuses)
                .bindArray("customStatuses", String.class, customStatuses)
                .bindArray("createdAts", Instant.class, createdAts)
                .bindArray("updatedAts", Instant.class, updatedAts)
                .bindArray("startedAts", Instant.class, startedAts)
                .bindArray("completedAts", Instant.class, completedAts)
                .executeAndReturnGeneratedKeys("ID")
                .mapTo(UUID.class)
                .list();
    }

    public WorkflowRunRow getRun(final UUID id) {
        final Query query = jdbiHandle.createQuery("""
                SELECT *
                  FROM "WORKFLOW_RUN"
                 WHERE "ID" = :id
                """);

        return query
                .bind("id", id)
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .findOne()
                .orElse(null);
    }

    public boolean existsRunWithNonTerminalStatus(final UUID id) {
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

    public Map<UUID, PolledWorkflowRunRow> pollAndLockRuns(
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
                       AND ("CONCURRENCY_GROUP_ID" IS NULL
                            OR "ID" = (SELECT "NEXT_RUN_ID"
                                         FROM "WORKFLOW_CONCURRENCY_GROUP" AS "WCG"
                                        WHERE "WCG"."ID" = "WORKFLOW_RUN"."CONCURRENCY_GROUP_ID"))
                       AND ("LOCKED_UNTIL" IS NULL OR "LOCKED_UNTIL" <= NOW())
                       AND EXISTS (SELECT 1
                                     FROM "WORKFLOW_RUN_INBOX"
                                    WHERE "WORKFLOW_RUN_ID" = "WORKFLOW_RUN"."ID"
                                      AND ("VISIBLE_FROM" IS NULL OR "VISIBLE_FROM" <= NOW()))
                     ORDER BY "PRIORITY" DESC NULLS LAST
                            , "CREATED_AT"
                       FOR NO KEY UPDATE
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
                        , "WORKFLOW_RUN"."CONCURRENCY_GROUP_ID"
                        , "WORKFLOW_RUN"."PRIORITY"
                        , "WORKFLOW_RUN"."TAGS"
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowName", workflowName)
                .bind("lockTimeout", lockTimeout)
                .bind("limit", limit)
                .executeAndReturnGeneratedKeys(
                        "ID",
                        "WORKFLOW_NAME",
                        "WORKFLOW_VERSION",
                        "CONCURRENCY_GROUP_ID",
                        "PRIORITY",
                        "TAGS")
                .map(new PolledWorkflowRunRowMapper())
                .collectToMap(PolledWorkflowRunRow::id, Function.identity());
    }

    public int unlockRun(final UUID workerInstanceId, final UUID workflowRunId) {
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

    public int createRunInboxEvents(final SequencedCollection<NewWorkflowRunInboxRow> newEvents) {
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "WORKFLOW_RUN_INBOX" (
                  "WORKFLOW_RUN_ID"
                , "VISIBLE_FROM"
                , "EVENT"
                )
                SELECT * FROM UNNEST(:runIds, :visibleFroms, :events)
                """);

        final var runIds = new ArrayList<UUID>(newEvents.size());
        final var visibleFroms = new ArrayList<Instant>(newEvents.size());
        final var events = new ArrayList<WorkflowEvent>(newEvents.size());
        for (final NewWorkflowRunInboxRow newEvent : newEvents) {
            runIds.add(newEvent.workflowRunId());
            visibleFroms.add(newEvent.visibleFrom());
            events.add(newEvent.event());
        }

        return update
                .registerArrayType(Instant.class, "TIMESTAMPTZ")
                .registerArrayType(new WorkflowEventSqlArrayType())
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("visibleFroms", Instant.class, visibleFroms)
                .bindArray("events", WorkflowEvent.class, events)
                .registerArgument(new WorkflowEventArgumentFactory())
                .execute();
    }

    public Map<UUID, PolledWorkflowEvents> pollRunEvents(
            final UUID workerInstanceId,
            final Collection<UUID> workflowRunIds) {
        final Query query = jdbiHandle.createQuery("""
                WITH
                "CTE_JOURNAL" AS (
                    SELECT "WORKFLOW_RUN_ID"
                         , "EVENT"
                      FROM "WORKFLOW_RUN_JOURNAL"
                     WHERE "WORKFLOW_RUN_ID" = ANY(:workflowRunIds)
                     ORDER BY "SEQUENCE_NUMBER"
                ),
                "CTE_INBOX_POLL_CANDIDATE" AS (
                    SELECT "ID"
                      FROM "WORKFLOW_RUN_INBOX"
                     WHERE "WORKFLOW_RUN_ID" = ANY(:workflowRunIds)
                       AND ("VISIBLE_FROM" IS NULL OR "VISIBLE_FROM" <= NOW())
                     ORDER BY "ID"
                       FOR NO KEY UPDATE
                      SKIP LOCKED
                ),
                "CTE_POLLED_INBOX" AS (
                    UPDATE "WORKFLOW_RUN_INBOX"
                       SET "LOCKED_BY" = :workerInstanceId
                         , "DEQUEUE_COUNT" = COALESCE("DEQUEUE_COUNT", 0) + 1
                      FROM "CTE_INBOX_POLL_CANDIDATE"
                     WHERE "CTE_INBOX_POLL_CANDIDATE"."ID" = "WORKFLOW_RUN_INBOX"."ID"
                    RETURNING "WORKFLOW_RUN_INBOX"."WORKFLOW_RUN_ID"
                            , "WORKFLOW_RUN_INBOX"."EVENT"
                            , "WORKFLOW_RUN_INBOX"."DEQUEUE_COUNT"
                )
                SELECT 'JOURNAL' AS "EVENT_TYPE"
                     , "WORKFLOW_RUN_ID"
                     , "EVENT"
                     , NULL AS "DEQUEUE_COUNT"
                  FROM "CTE_JOURNAL"
                 UNION ALL
                SELECT 'INBOX' AS "EVENT_TYPE"
                     , "WORKFLOW_RUN_ID"
                     , "EVENT"
                     , "DEQUEUE_COUNT"
                  FROM "CTE_POLLED_INBOX"
                """);

        final List<PolledWorkflowEventRow> polledEventRows = query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .map(new PolledWorkflowEventRowMapper())
                .list();

        final var journalByRunId = new HashMap<UUID, List<WorkflowEvent>>(workflowRunIds.size());
        final var inboxByRunId = new HashMap<UUID, List<WorkflowEvent>>(workflowRunIds.size());
        final var maxInboxEventDequeueCountByRunId = new HashMap<UUID, Integer>(workflowRunIds.size());

        for (final PolledWorkflowEventRow row : polledEventRows) {
            switch (row.eventType()) {
                case JOURNAL -> journalByRunId.computeIfAbsent(
                        row.workflowRunId(), ignored -> new ArrayList<>()).add(row.event());
                case INBOX -> {
                    inboxByRunId.computeIfAbsent(
                            row.workflowRunId(), ignored -> new ArrayList<>()).add(row.event());

                    maxInboxEventDequeueCountByRunId.compute(
                            row.workflowRunId(),
                            (ignored, previousMax) -> (previousMax == null || previousMax < row.dequeueCount())
                                    ? row.dequeueCount()
                                    : previousMax);
                }
            }
        }

        final var polledEventsByRunId = new HashMap<UUID, PolledWorkflowEvents>(workflowRunIds.size());
        for (final UUID runId : workflowRunIds) {
            polledEventsByRunId.put(runId, new PolledWorkflowEvents(
                    journalByRunId.getOrDefault(runId, Collections.emptyList()),
                    inboxByRunId.getOrDefault(runId, Collections.emptyList()),
                    maxInboxEventDequeueCountByRunId.getOrDefault(runId, 0)));
        }

        return polledEventsByRunId;
    }

    public List<WorkflowEvent> getRunInbox(final UUID workflowRunId) {
        final Query query = jdbiHandle.createQuery("""
                SELECT "EVENT"
                  FROM "WORKFLOW_RUN_INBOX"
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                 ORDER BY "ID"
                """);

        return query
                .bind("workflowRunId", workflowRunId)
                .map(new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .list();
    }

    public int unlockRunInboxEvents(
            final UUID workerInstanceId,
            final UUID workflowRunId,
            final Duration visibilityDelay) {
        final Update update = jdbiHandle.createUpdate("""
                UPDATE "WORKFLOW_RUN_INBOX"
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

    public int deleteRunInboxEvents(
            final UUID workerInstanceId,
            final Collection<DeleteInboxEventsCommand> deleteCommands) {
        final Update update = jdbiHandle.createUpdate("""
                DELETE
                  FROM "WORKFLOW_RUN_INBOX"
                 USING UNNEST(:workflowRunIds, :onlyLockeds) AS "DELETE_COMMAND" ("WORKFLOW_RUN_ID", "ONLY_LOCKED")
                 WHERE "WORKFLOW_RUN_INBOX"."WORKFLOW_RUN_ID" = "DELETE_COMMAND"."WORKFLOW_RUN_ID"
                   AND (NOT "DELETE_COMMAND"."ONLY_LOCKED"
                         OR "WORKFLOW_RUN_INBOX"."LOCKED_BY" = :workerInstanceId)
                """);

        final var runIds = new ArrayList<UUID>(deleteCommands.size());
        final var onlyLockeds = new ArrayList<Boolean>(deleteCommands.size());
        for (final DeleteInboxEventsCommand command : deleteCommands) {
            runIds.add(command.workflowRunId());
            onlyLockeds.add(command.onlyLocked());
        }

        return update
                .bindArray("workflowRunIds", UUID.class, runIds)
                .bindArray("onlyLockeds", Boolean.class, onlyLockeds)
                .bind("workerInstanceId", workerInstanceId.toString())
                .execute();
    }

    public int createRunJournalEntries(final Collection<NewWorkflowRunJournalRow> newJournalEntries) {
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "WORKFLOW_RUN_JOURNAL" (
                  "WORKFLOW_RUN_ID"
                , "SEQUENCE_NUMBER"
                , "EVENT"
                )
                SELECT * FROM UNNEST(:runIds, :sequenceNumbers, :events)
                """);

        final var runIds = new ArrayList<UUID>(newJournalEntries.size());
        final var sequenceNumbers = new ArrayList<Integer>(newJournalEntries.size());
        final var events = new ArrayList<WorkflowEvent>(newJournalEntries.size());
        for (final NewWorkflowRunJournalRow newJournalEntry : newJournalEntries) {
            runIds.add(newJournalEntry.workflowRunId());
            sequenceNumbers.add(newJournalEntry.sequenceNumber());
            events.add(newJournalEntry.event());
        }

        return update
                .registerArrayType(new WorkflowEventSqlArrayType())
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("sequenceNumbers", Integer.class, sequenceNumbers)
                .bindArray("events", WorkflowEvent.class, events)
                .execute();
    }

    public List<WorkflowEvent> getRunJournal(final UUID runId) {
        final Query query = jdbiHandle.createQuery("""
                SELECT "EVENT"
                  FROM "WORKFLOW_RUN_JOURNAL"
                 WHERE "WORKFLOW_RUN_ID" = :runId
                 ORDER BY "SEQUENCE_NUMBER"
                """);

        return query
                .bind("runId", runId)
                .map(new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .list();
    }

    public int createActivityTasks(final Collection<NewActivityTaskRow> newTasks) {
        final Update update = jdbiHandle.createUpdate("""
                INSERT INTO "WORKFLOW_ACTIVITY_TASK" (
                  "WORKFLOW_RUN_ID"
                , "SCHEDULED_EVENT_ID"
                , "ACTIVITY_NAME"
                , "PRIORITY"
                , "ARGUMENT"
                , "VISIBLE_FROM"
                , "CREATED_AT"
                )
                SELECT *
                     , NOW()
                  FROM UNNEST (
                         :runIds
                       , :scheduledEventIds
                       , :activityNames
                       , :priorities
                       , :arguments
                       , :visibleFroms)
                """);

        final var runIds = new ArrayList<UUID>(newTasks.size());
        final var scheduledEventIds = new ArrayList<Integer>(newTasks.size());
        final var activityNames = new ArrayList<String>(newTasks.size());
        final var priorities = new ArrayList<Integer>(newTasks.size());
        final var arguments = new ArrayList<WorkflowPayload>(newTasks.size());
        final var visibleFroms = new ArrayList<Instant>(newTasks.size());
        for (final NewActivityTaskRow newTask : newTasks) {
            runIds.add(newTask.workflowRunId());
            scheduledEventIds.add(newTask.scheduledEventId());
            activityNames.add(newTask.activityName());
            priorities.add(newTask.priority());
            arguments.add(newTask.argument());
            visibleFroms.add(newTask.visibleFrom());
        }

        return update
                .registerArrayType(Instant.class, "TIMESTAMPTZ")
                .registerArrayType(new WorkflowPayloadSqlArrayType())
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("scheduledEventIds", Integer.class, scheduledEventIds)
                .bindArray("activityNames", String.class, activityNames)
                .bindArray("priorities", Integer.class, priorities)
                .bindArray("arguments", WorkflowPayload.class, arguments)
                .bindArray("visibleFroms", Instant.class, visibleFroms)
                .execute();
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
                       FOR NO KEY UPDATE
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
                .map(new PolledActivityTaskRowMapper())
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
