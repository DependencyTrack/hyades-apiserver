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

import alpine.persistence.OrderDirection;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.WorkflowRunStatus;
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
                insert into workflow_run (
                  id
                , parent_id
                , workflow_name
                , workflow_version
                , concurrency_group_id
                , priority
                , tags
                )
                select id
                     , parent_id
                     , workflow_name
                     , workflow_version
                     , concurrency_group_id
                     , priority
                     , (select array_agg(tag)
                          from json_array_elements_text(tags) as tag) as tags
                  from unnest (
                         :ids
                       , :parentIds
                       , :workflowNames
                       , :workflowVersions
                       , :concurrencyGroupIds
                       , :priorities
                       , cast(:tagsJsons as json[])
                       ) as new_run (
                         id
                       , parent_id
                       , workflow_name
                       , workflow_version
                       , concurrency_group_id
                       , priority
                       , tags)
                returning id
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
                .executeAndReturnGeneratedKeys("id")
                .mapTo(UUID.class)
                .list();
    }

    public int maybeCreateConcurrencyGroups(final Collection<WorkflowConcurrencyGroupRow> concurrencyGroups) {
        // NB: We must *not* use ON CONFLICT DO UPDATE here, since we have to assume that the
        // existing NEXT_RUN_ID is already being worked on, even if it technically orders
        // *after* the run ID we're trying to insert here.
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_concurrency_group (
                  id
                , next_run_id
                )
                select * from unnest(:groupIds, :nextRunIds)
                on conflict (id) do nothing
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
                with
                cte_next_run as (
                    select distinct on (concurrency_group_id)
                           concurrency_group_id
                         , id
                      from workflow_run
                     where concurrency_group_id = any(:groupIds)
                       and status = any('{PENDING, RUNNING, SUSPENDED}'::workflow_run_status[])
                     order by concurrency_group_id
                            , priority desc nulls last
                            , created_at
                ),
                cte_updated_group as (
                    update workflow_concurrency_group
                       set next_run_id = cte_next_run.id
                      from cte_next_run
                     where workflow_concurrency_group.id = cte_next_run.concurrency_group_id
                    returning workflow_concurrency_group.id
                ),
                cte_deleted_group as (
                   delete
                     from workflow_concurrency_group
                    where id = any(:groupIds)
                      and id != all(select id from cte_updated_group)
                   returning id
                )
                select id
                     , 'UPDATED' as status
                  from cte_updated_group
                 union all
                select id
                     , 'DELETED' as status
                  from cte_deleted_group
                """);

        return query
                .setMapKeyColumn("id")
                .setMapValueColumn("status")
                .bindArray("groupIds", String.class, concurrencyGroupIds)
                .collectInto(new GenericType<>() {
                });
    }

    public List<WorkflowRunListRow> getRunListPage(
            final String workflowNameFilter,
            final WorkflowRunStatus statusFilter,
            final String concurrencyGroupIdFilter,
            final Set<String> tagsFilter,
            final String orderBy,
            final OrderDirection orderDirection,
            final int offset,
            final int limit) {
        // TODO: Use a more JDBI-native and more safe way to do this.
        final String orderDirectionStr = orderDirection == OrderDirection.DESCENDING ? "desc nulls last" : "";
        final String orderByClause = switch (orderBy) {
            case "createdAt" -> "created_at";
            case "startedAt" -> "started_at";
            case "completedAt" -> "completed_at";
            default -> "updated_at ";
        } + " " + orderDirectionStr;

        // TODO: Ordering by user-defined field.
        final Query query = jdbiHandle.createQuery(/* language=SQL */ """
                select id as id
                     , workflow_name
                     , workflow_version
                     , status
                     , custom_status
                     , concurrency_group_id
                     , priority
                     , tags
                     , created_at
                     , updated_at
                     , started_at
                     , completed_at
                     , count(*) over() as total_count
                  from workflow_run
                 where 1 = 1
                   and (:workflowNameFilter IS NULL OR workflow_name = :workflowNameFilter)
                   and (cast(:statusFilter as workflow_run_status) IS NULL OR status = cast(:statusFilter as workflow_run_status))
                   and (:concurrencyGroupIdFilter IS NULL OR concurrency_group_id = :concurrencyGroupIdFilter)
                   and (cast(:tagsFilter as text[]) IS NULL OR tags @> cast(:tagsFilter as text[]))
                 order by %s
                offset :offset fetch next :limit rows only
                """.formatted(orderByClause));

        return query
                .bind("workflowNameFilter", workflowNameFilter)
                .bind("statusFilter", statusFilter)
                .bind("concurrencyGroupIdFilter", concurrencyGroupIdFilter)
                .bindArray("tagsFilter", String.class, tagsFilter)
                .bind("offset", offset)
                .bind("limit", limit)
                .map(ConstructorMapper.of(WorkflowRunListRow.class))
                .list();
    }

    public List<WorkflowRunCountByNameAndStatusRow> getRunCountByNameAndStatus() {
        final Query query = jdbiHandle.createQuery("""
                select workflow_name
                     , status
                     , count(*)
                  from workflow_run
                 group by workflow_name
                        , status
                """);

        return query
                .map(ConstructorMapper.of(WorkflowRunCountByNameAndStatusRow.class))
                .list();
    }

    public List<UUID> updateRuns(
            final UUID workerInstanceId,
            final Collection<WorkflowRunRowUpdate> runUpdates) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_run
                   set status = coalesce(run_update.status, workflow_run.status)
                     , custom_status = coalesce(run_update.custom_status, workflow_run.custom_status)
                     , locked_by = null
                     , locked_until = null
                     , created_at = coalesce(run_update.created_at, workflow_run.created_at)
                     , updated_at = coalesce(run_update.updated_at, workflow_run.updated_at)
                     , started_at = coalesce(run_update.started_at, workflow_run.started_at)
                     , completed_at = coalesce(run_update.completed_at, workflow_run.completed_at)
                  from unnest (
                         :ids
                       , :statuses
                       , :customStatuses
                       , :createdAts
                       , :updatedAts
                       , :startedAts
                       , :completedAts
                       ) as run_update (
                         id
                       , status
                       , custom_status
                       , created_at
                       , updated_at
                       , started_at
                       , completed_at)
                 where workflow_run.id = run_update.id
                   and workflow_run.locked_by = :workerInstanceId
                returning workflow_run.id
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
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("ids", UUID.class, ids)
                .bindArray("statuses", WorkflowRunStatus.class, statuses)
                .bindArray("customStatuses", String.class, customStatuses)
                .bindArray("createdAts", Instant.class, createdAts)
                .bindArray("updatedAts", Instant.class, updatedAts)
                .bindArray("startedAts", Instant.class, startedAts)
                .bindArray("completedAts", Instant.class, completedAts)
                .executeAndReturnGeneratedKeys("id")
                .mapTo(UUID.class)
                .list();
    }

    public WorkflowRunRow getRun(final UUID id) {
        final Query query = jdbiHandle.createQuery("""
                select *
                  from workflow_run
                 where id = :id
                """);

        return query
                .bind("id", id)
                .map(ConstructorMapper.of(WorkflowRunRow.class))
                .findOne()
                .orElse(null);
    }

    public boolean existsRunWithNonTerminalStatus(final UUID id) {
        final Query query = jdbiHandle.createQuery("""
                select exists (
                    select 1
                      from workflow_run
                     where id = :id
                       and status = any(cast('{PENDING, RUNNING, SUSPENDED}' as workflow_run_status[])))
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
                with cte_poll as (
                    select id
                      from workflow_run
                     where workflow_name = :workflowName
                       and status = any(cast('{PENDING, RUNNING, SUSPENDED}' as workflow_run_status[]))
                       and (concurrency_group_id is null
                            or id = (select next_run_id
                                       from workflow_concurrency_group as wcg
                                      where wcg.id = workflow_run.concurrency_group_id))
                       and (locked_until is null or locked_until <= now())
                       and exists (select 1
                                     from workflow_run_inbox
                                    where workflow_run_id = workflow_run.id
                                      and (visible_from is null or visible_from <= now()))
                     order by priority desc nulls last
                            , created_at
                       for no key update
                      skip locked
                     limit :limit)
                update workflow_run
                   set locked_by = :workerInstanceId
                     , locked_until = now() + :lockTimeout
                  from cte_poll
                 where cte_poll.id = workflow_run.id
                returning workflow_run.id
                        , workflow_run.workflow_name
                        , workflow_run.workflow_version
                        , workflow_run.concurrency_group_id
                        , workflow_run.priority
                        , workflow_run.tags
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowName", workflowName)
                .bind("lockTimeout", lockTimeout)
                .bind("limit", limit)
                .executeAndReturnGeneratedKeys(
                        "id",
                        "workflow_name",
                        "workflow_version",
                        "concurrency_group_id",
                        "priority",
                        "tags")
                .mapTo(PolledWorkflowRunRow.class)
                .collectToMap(PolledWorkflowRunRow::id, Function.identity());
    }

    public int unlockRun(final UUID workerInstanceId, final UUID workflowRunId) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_run
                   set locked_by = null
                     , locked_until = null
                 where id = :workflowRunId
                   and locked_by = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowRunId", workflowRunId)
                .execute();
    }

    public int createRunInboxEvents(final SequencedCollection<NewWorkflowRunInboxRow> newEvents) {
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_run_inbox (
                  workflow_run_id
                , visible_from
                , event
                )
                select * from unnest(:runIds, :visibleFroms, :events)
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
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("visibleFroms", Instant.class, visibleFroms)
                .bindArray("events", WorkflowEvent.class, events)
                .execute();
    }

    public Map<UUID, PolledWorkflowEvents> pollRunEvents(
            final UUID workerInstanceId,
            final Collection<UUID> workflowRunIds) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_journal as (
                    select workflow_run_id
                         , event
                      from workflow_run_journal
                     where workflow_run_id = any(:workflowRunIds)
                     order by sequence_number
                ),
                cte_inbox_poll_candidate as (
                    select id
                      from workflow_run_inbox
                     where workflow_run_id = any(:workflowRunIds)
                       and (visible_from is null or visible_from <= now())
                     order by id
                       for no key update
                      skip locked
                ),
                cte_polled_inbox as (
                    update workflow_run_inbox
                       set locked_by = :workerInstanceId
                         , dequeue_count = coalesce(dequeue_count, 0) + 1
                      from cte_inbox_poll_candidate
                     where cte_inbox_poll_candidate.id = workflow_run_inbox.id
                    returning workflow_run_inbox.workflow_run_id
                            , workflow_run_inbox.event
                            , workflow_run_inbox.dequeue_count
                )
                select 'JOURNAL' as event_type
                     , workflow_run_id
                     , event
                     , null as dequeue_count
                  from cte_journal
                 union all
                select 'INBOX' as event_type
                     , workflow_run_id
                     , event
                     , dequeue_count
                  from cte_polled_inbox
                """);

        final List<PolledWorkflowEventRow> polledEventRows = query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .mapTo(PolledWorkflowEventRow.class)
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
                select event
                  from workflow_run_inbox
                 where workflow_run_id = :workflowRunId
                 order by id
                """);

        return query
                .bind("workflowRunId", workflowRunId)
                .mapTo(WorkflowEvent.class)
                .list();
    }

    public int unlockRunInboxEvents(
            final UUID workerInstanceId,
            final UUID workflowRunId,
            final Duration visibilityDelay) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_run_inbox
                   set locked_by = null
                     , visible_from = now() + :visibilityDelay
                 where workflow_run_id = :workflowRunId
                   and locked_by = :workerInstanceId
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
                delete
                  from workflow_run_inbox
                 using unnest(:workflowRunIds, :onlyLockeds) as delete_command (workflow_run_id, only_locked)
                 where workflow_run_inbox.workflow_run_id = delete_command.workflow_run_id
                   and (not delete_command.only_locked
                         or workflow_run_inbox.locked_by = :workerInstanceId)
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
                insert into workflow_run_journal (
                  workflow_run_id
                , sequence_number
                , event
                )
                select * from unnest(:runIds, :sequenceNumbers, :events)
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
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("sequenceNumbers", Integer.class, sequenceNumbers)
                .bindArray("events", WorkflowEvent.class, events)
                .execute();
    }

    public List<WorkflowEvent> getRunJournal(final UUID runId) {
        final Query query = jdbiHandle.createQuery("""
                select event
                  from workflow_run_journal
                 where workflow_run_id = :runId
                 order by sequence_number
                """);

        return query
                .bind("runId", runId)
                .mapTo(WorkflowEvent.class)
                .list();
    }

    public int createActivityTasks(final Collection<NewActivityTaskRow> newTasks) {
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_activity_task (
                  workflow_run_id
                , scheduled_event_id
                , activity_name
                , priority
                , argument
                , visible_from
                , created_at
                )
                select *
                     , now()
                  from unnest (
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
                with cte_poll as (
                    select workflow_run_id
                         , scheduled_event_id
                      from workflow_activity_task
                     where activity_name = :activityName
                       and (visible_from is null or visible_from <= now())
                       and (locked_until is null or locked_until <= now())
                     order by priority desc nulls last
                            , created_at
                       for no key update
                      skip locked
                     limit :limit)
                update workflow_activity_task as wat
                   set locked_by = :workerInstanceId
                     , locked_until = now() + :lockTimeout
                     , updated_at = now()
                  from cte_poll
                 where cte_poll.workflow_run_id = wat.workflow_run_id
                   and cte_poll.scheduled_event_id = wat.scheduled_event_id
                returning wat.workflow_run_id
                        , wat.scheduled_event_id
                        , wat.activity_name
                        , wat.priority
                        , wat.argument
                        , wat.locked_until
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("activityName", activityName)
                .bind("lockTimeout", lockTimeout)
                .bind("limit", limit)
                .executeAndReturnGeneratedKeys(
                        "workflow_run_id",
                        "scheduled_event_id",
                        "activity_name",
                        "priority",
                        "argument",
                        "locked_until")
                .mapTo(PolledActivityTaskRow.class)
                .list();
    }

    public Instant extendActivityTaskLock(
            final UUID workerInstanceId,
            final ActivityTaskId activityTask,
            final Duration lockTimeout) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_activity_task
                   set locked_until = locked_until + :lockTimeout
                     , updated_at = now()
                 where workflow_run_id = :workflowRunId
                   and scheduled_event_id = :scheduledEventId
                   and locked_by = :workerInstanceId
                returning locked_until
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowRunId", activityTask.workflowRunId())
                .bind("scheduledEventId", activityTask.scheduledEventId())
                .bind("lockTimeout", lockTimeout)
                .executeAndReturnGeneratedKeys("locked_until")
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
                with cte as (
                    select *
                      from unnest(:workflowRunIds, :scheduledEventIds) as t(workflow_run_id, scheduled_event_id))
                update workflow_activity_task
                   set locked_by = null
                     , locked_until = null
                  from cte
                 where cte.workflow_run_id = workflow_activity_task.workflow_run_id
                   and cte.scheduled_event_id = workflow_activity_task.scheduled_event_id
                   and workflow_activity_task.locked_by = :workerInstanceId
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
                with cte as (
                    select *
                      from unnest(:workflowRunIds, :scheduledEventIds) as t(workflow_run_id, scheduled_event_id))
                delete
                  from workflow_activity_task
                 using cte
                 where cte.workflow_run_id = workflow_activity_task.workflow_run_id
                   and cte.scheduled_event_id = workflow_activity_task.scheduled_event_id
                   and workflow_activity_task.locked_by = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bindArray("scheduledEventIds", Integer.class, scheduledEventIds)
                .execute();
    }

}
