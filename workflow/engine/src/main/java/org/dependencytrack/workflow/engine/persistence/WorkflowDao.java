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
package org.dependencytrack.workflow.engine.persistence;

import org.dependencytrack.workflow.api.proto.v1.WorkflowEvent;
import org.dependencytrack.workflow.engine.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.persistence.model.DeleteInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.model.GetWorkflowRunJournalRequest;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowRunInboxRow;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowRunJournalRow;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.PollWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEventRow;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.UnlockWorkflowRunInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowConcurrencyGroupRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRowUpdate;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
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
                , labels
                )
                select *
                  from unnest (
                         :ids
                       , :parentIds
                       , :workflowNames
                       , :workflowVersions
                       , :concurrencyGroupIds
                       , :priorities
                       , cast(:labelsJsons as jsonb[])
                       )
                returning id
                """);

        final var ids = new ArrayList<UUID>(newRuns.size());
        final var parentIds = new ArrayList<UUID>(newRuns.size());
        final var workflowNames = new ArrayList<String>(newRuns.size());
        final var workflowVersions = new ArrayList<Integer>(newRuns.size());
        final var concurrencyGroupIds = new ArrayList<String>(newRuns.size());
        final var priorities = new ArrayList<Integer>(newRuns.size());
        final var labelsJsons = new ArrayList<String>(newRuns.size());

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class).getJsonMapper()
                .forType(new GenericType<Map<String, String>>() {
                }.getType(), jdbiHandle.getConfig());

        for (final NewWorkflowRunRow newRun : newRuns) {
            final String labelsJson;
            if (newRun.labels() == null || newRun.labels().isEmpty()) {
                labelsJson = null;
            } else {
                labelsJson = jsonMapper.toJson(newRun.labels(), jdbiHandle.getConfig());
            }

            ids.add(newRun.id());
            parentIds.add(newRun.parentId());
            workflowNames.add(newRun.workflowName());
            workflowVersions.add(newRun.workflowVersion());
            concurrencyGroupIds.add(newRun.concurrencyGroupId());
            priorities.add(newRun.priority());
            labelsJsons.add(labelsJson);
        }

        return update
                .bindArray("ids", UUID.class, ids)
                .bindArray("parentIds", UUID.class, parentIds)
                .bindArray("workflowNames", String.class, workflowNames)
                .bindArray("workflowVersions", Integer.class, workflowVersions)
                .bindArray("concurrencyGroupIds", String.class, concurrencyGroupIds)
                .bindArray("priorities", Integer.class, priorities)
                .bindArray("labelsJsons", String.class, labelsJsons)
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
                            , id
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
                .mapTo(WorkflowRunCountByNameAndStatusRow.class)
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
                .mapTo(WorkflowRunRow.class)
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
            final Collection<PollWorkflowTaskCommand> pollCommands,
            final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                with cte_poll as (
                  select id
                    from workflow_run
                   where workflow_name = any(:workflowNames)
                     and status = any(cast('{PENDING, RUNNING, SUSPENDED}' as workflow_run_status[]))
                     and (concurrency_group_id is null
                          or exists (
                               select 1
                                 from workflow_concurrency_group as wcg
                                where wcg.id = workflow_run.concurrency_group_id
                                  and wcg.next_run_id = workflow_run.id
                             )
                         )
                     and (locked_until is null or locked_until <= now())
                     and exists (
                           select 1
                             from workflow_run_inbox
                            where workflow_run_id = workflow_run.id
                              and (visible_from is null or visible_from <= now())
                         )
                   order by priority desc nulls last
                          , id
                     for no key update of workflow_run
                    skip locked
                   limit :limit
                )
                update workflow_run
                   set locked_by = :workerInstanceId
                     , locked_until = now() + (
                         select t.lock_timeout
                           from unnest(:workflowNames, :lockTimeouts) as t(workflow_name, lock_timeout)
                          where t.workflow_name = workflow_run.workflow_name
                          limit 1
                       )
                  from cte_poll
                 where cte_poll.id = workflow_run.id
                returning workflow_run.id
                        , workflow_run.workflow_name
                        , workflow_run.workflow_version
                        , workflow_run.concurrency_group_id
                        , workflow_run.priority
                        , workflow_run.labels
                """);

        final var workflowNames = new ArrayList<String>(pollCommands.size());
        final var lockTimeouts = new ArrayList<Duration>(pollCommands.size());

        for (final PollWorkflowTaskCommand pollCommand : pollCommands) {
            workflowNames.add(pollCommand.workflowName());
            lockTimeouts.add(pollCommand.lockTimeout());
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowNames", String.class, workflowNames)
                .bindArray("lockTimeouts", Duration.class, lockTimeouts)
                .bind("limit", limit)
                .executeAndReturnGeneratedKeys(
                        "id",
                        "workflow_name",
                        "workflow_version",
                        "concurrency_group_id",
                        "priority",
                        "labels")
                .mapTo(PolledWorkflowRunRow.class)
                .collectToMap(PolledWorkflowRunRow::id, Function.identity());
    }

    public int unlockRuns(final UUID workerInstanceId, final Collection<UUID> runIds) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_run
                   set locked_by = null
                     , locked_until = null
                 where id = any(:runIds)
                   and locked_by = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("runIds", UUID.class, runIds)
                .execute();
    }

    public int deleteExpiredRuns(final Instant cutoff, final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                with cte_candidates as (
                  select id
                    from workflow_run
                   where completed_at < :cutoff
                   order by completed_at
                   limit :limit
                )
                delete
                  from workflow_run
                 where id in (select id from cte_candidates)
                """);

        return update
                .bind("cutoff", cutoff)
                .bind("limit", limit)
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
            final Collection<GetWorkflowRunJournalRequest> journalRequests) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_journal as (
                    select workflow_run_journal.workflow_run_id
                         , event
                         , sequence_number
                      from workflow_run_journal
                     inner join unnest(:journalRequestRunIds, :journalRequestOffsets) as request(run_id, "offset")
                        on request.run_id = workflow_run_journal.workflow_run_id
                       and request."offset" < workflow_run_journal.sequence_number
                     order by sequence_number
                ),
                cte_inbox_poll_candidate as (
                    select id
                      from workflow_run_inbox
                     where workflow_run_id = any(:journalRequestRunIds)
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
                     , sequence_number
                     , null as dequeue_count
                  from cte_journal
                 union all
                select 'INBOX' as event_type
                     , workflow_run_id
                     , event
                     , null as sequence_number
                     , dequeue_count
                  from cte_polled_inbox
                """);

        final var journalRequestRunIds = new ArrayList<UUID>(journalRequests.size());
        final var journalRequestOffsets = new ArrayList<Integer>(journalRequests.size());
        for (final GetWorkflowRunJournalRequest journalRequest : journalRequests) {
            journalRequestRunIds.add(journalRequest.runId());
            journalRequestOffsets.add(journalRequest.offset());
        }

        final List<PolledWorkflowEventRow> polledEventRows = query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("journalRequestRunIds", UUID.class, journalRequestRunIds)
                .bindArray("journalRequestOffsets", Integer.class, journalRequestOffsets)
                .mapTo(PolledWorkflowEventRow.class)
                .list();

        final var journalByRunId = new HashMap<UUID, List<WorkflowEvent>>(journalRequests.size());
        final var inboxByRunId = new HashMap<UUID, List<WorkflowEvent>>(journalRequests.size());
        final var maxJournalEventSequenceNumberByRunId = new HashMap<UUID, Integer>(journalRequests.size());
        final var maxInboxEventDequeueCountByRunId = new HashMap<UUID, Integer>(journalRequests.size());

        for (final PolledWorkflowEventRow row : polledEventRows) {
            switch (row.eventType()) {
                case JOURNAL -> {
                    journalByRunId.computeIfAbsent(
                            row.workflowRunId(), ignored -> new ArrayList<>()).add(row.event());

                    maxJournalEventSequenceNumberByRunId.compute(
                            row.workflowRunId(),
                            (ignored, previousMax) -> (previousMax == null || previousMax < row.journalSequenceNumber())
                                    ? row.journalSequenceNumber()
                                    : previousMax);
                }
                case INBOX -> {
                    inboxByRunId.computeIfAbsent(
                            row.workflowRunId(), ignored -> new ArrayList<>()).add(row.event());

                    maxInboxEventDequeueCountByRunId.compute(
                            row.workflowRunId(),
                            (ignored, previousMax) -> (previousMax == null || previousMax < row.inboxDequeueCount())
                                    ? row.inboxDequeueCount()
                                    : previousMax);
                }
            }
        }

        final var polledEventsByRunId = new HashMap<UUID, PolledWorkflowEvents>(journalRequests.size());
        for (final UUID runId : journalRequestRunIds) {
            polledEventsByRunId.put(runId, new PolledWorkflowEvents(
                    journalByRunId.getOrDefault(runId, Collections.emptyList()),
                    inboxByRunId.getOrDefault(runId, Collections.emptyList()),
                    maxJournalEventSequenceNumberByRunId.getOrDefault(runId, -1),
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
            final Collection<UnlockWorkflowRunInboxEventsCommand> unlockCommands) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_run_inbox
                   set locked_by = null
                     , visible_from = now() + t.visibility_delay
                  from unnest(:runIds, :visibilityDelays) as t(run_id, visibility_delay)
                 where workflow_run_id = t.run_id
                   and locked_by = :workerInstanceId
                """);

        final var runIds = new ArrayList<UUID>(unlockCommands.size());
        final var visibilityDelays = new ArrayList<Duration>(unlockCommands.size());

        for (final UnlockWorkflowRunInboxEventsCommand command : unlockCommands) {
            runIds.add(command.workflowRunId());
            visibilityDelays.add(command.visibilityDelay());
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("visibilityDelays", Duration.class, visibilityDelays)
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

    public int truncateRunJournals(final Collection<UUID> runIds) {
        final Update update = jdbiHandle.createUpdate("""
                delete from workflow_run_journal
                 where workflow_run_id = any(:runIds)
                """);

        return update
                .bindArray("runIds", UUID.class, runIds)
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

    public boolean tryAcquireAdvisoryLock(final String lockName) {
        if (!jdbiHandle.isInTransaction()) {
            throw new IllegalStateException("Must be in transaction to acquire advisory lock");
        }

        final Query query = jdbiHandle.createQuery("""
                select pg_try_advisory_xact_lock(:lockId)
                """);

        return query
                .bind("lockId", lockName.hashCode())
                .mapTo(Boolean.class)
                .one();
    }

}
