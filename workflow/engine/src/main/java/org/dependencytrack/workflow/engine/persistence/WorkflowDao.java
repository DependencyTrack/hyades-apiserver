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

import org.dependencytrack.proto.workflow.event.v1.Event;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.persistence.command.CreateWorkflowRunCommand;
import org.dependencytrack.workflow.engine.persistence.command.CreateWorkflowRunHistoryEntryCommand;
import org.dependencytrack.workflow.engine.persistence.command.CreateWorkflowRunInboxEntryCommand;
import org.dependencytrack.workflow.engine.persistence.command.DeleteInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.command.PollWorkflowTaskCommand;
import org.dependencytrack.workflow.engine.persistence.command.UnlockWorkflowRunInboxEventsCommand;
import org.dependencytrack.workflow.engine.persistence.command.UpdateAndUnlockRunCommand;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEvent;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowRun;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunMetadataRow;
import org.dependencytrack.workflow.engine.persistence.request.GetWorkflowRunHistoryRequest;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;
import org.jspecify.annotations.Nullable;

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

public final class WorkflowDao extends AbstractDao {

    public WorkflowDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    public List<UUID> createRuns(final Collection<CreateWorkflowRunCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_run (
                  id
                , parent_id
                , workflow_name
                , workflow_version
                , concurrency_group_id
                , priority
                , labels
                , created_at
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
                       , :createdAts
                       )
                returning id
                """);

        final var ids = new ArrayList<UUID>(commands.size());
        final var parentIds = new ArrayList<@Nullable UUID>(commands.size());
        final var workflowNames = new ArrayList<String>(commands.size());
        final var workflowVersions = new ArrayList<Integer>(commands.size());
        final var concurrencyGroupIds = new ArrayList<@Nullable String>(commands.size());
        final var priorities = new ArrayList<@Nullable Integer>(commands.size());
        final var labelsJsons = new ArrayList<@Nullable String>(commands.size());
        final var createdAts = new ArrayList<Instant>(commands.size());

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class).getJsonMapper()
                .forType(new GenericType<Map<String, String>>() {
                }.getType(), jdbiHandle.getConfig());

        for (final CreateWorkflowRunCommand command : commands) {
            final String labelsJson;
            if (command.labels() == null || command.labels().isEmpty()) {
                labelsJson = null;
            } else {
                labelsJson = jsonMapper.toJson(command.labels(), jdbiHandle.getConfig());
            }

            ids.add(command.id());
            parentIds.add(command.parentId());
            workflowNames.add(command.workflowName());
            workflowVersions.add(command.workflowVersion());
            concurrencyGroupIds.add(command.concurrencyGroupId());
            priorities.add(command.priority());
            labelsJsons.add(labelsJson);
            createdAts.add(command.createdAt());
        }

        return update
                .bindArray("ids", UUID.class, ids)
                .bindArray("parentIds", UUID.class, parentIds)
                .bindArray("workflowNames", String.class, workflowNames)
                .bindArray("workflowVersions", Integer.class, workflowVersions)
                .bindArray("concurrencyGroupIds", String.class, concurrencyGroupIds)
                .bindArray("priorities", Integer.class, priorities)
                .bindArray("labelsJsons", String.class, labelsJsons)
                .bindArray("createdAts", Instant.class, createdAts)
                .executeAndReturnGeneratedKeys("id")
                .mapTo(UUID.class)
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
                .mapTo(WorkflowRunCountByNameAndStatusRow.class)
                .list();
    }

    public List<UUID> updateAndUnlockRuns(
            final UUID workerInstanceId,
            final Collection<UpdateAndUnlockRunCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_run
                   set status = coalesce(run_update.status, workflow_run.status)
                     , custom_status = coalesce(run_update.custom_status, workflow_run.custom_status)
                     , locked_by = null
                     , locked_until = null
                     , updated_at = coalesce(run_update.updated_at, workflow_run.updated_at)
                     , started_at = coalesce(run_update.started_at, workflow_run.started_at)
                     , completed_at = coalesce(run_update.completed_at, workflow_run.completed_at)
                  from unnest (
                         :ids
                       , :statuses
                       , :customStatuses
                       , :updatedAts
                       , :startedAts
                       , :completedAts
                       ) as run_update (
                         id
                       , status
                       , custom_status
                       , updated_at
                       , started_at
                       , completed_at
                       )
                 where workflow_run.id = run_update.id
                   and workflow_run.locked_by = :workerInstanceId
                returning workflow_run.id
                """);

        final var ids = new ArrayList<UUID>(commands.size());
        final var statuses = new ArrayList<WorkflowRunStatus>(commands.size());
        final var customStatuses = new ArrayList<@Nullable String>(commands.size());
        final var updatedAts = new ArrayList<@Nullable Instant>(commands.size());
        final var startedAts = new ArrayList<@Nullable Instant>(commands.size());
        final var completedAts = new ArrayList<@Nullable Instant>(commands.size());

        for (final UpdateAndUnlockRunCommand command : commands) {
            ids.add(command.id());
            statuses.add(command.status());
            customStatuses.add(command.customStatus());
            updatedAts.add(command.updatedAt());
            startedAts.add(command.startedAt());
            completedAts.add(command.completedAt());
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("ids", UUID.class, ids)
                .bindArray("statuses", WorkflowRunStatus.class, statuses)
                .bindArray("customStatuses", String.class, customStatuses)
                .bindArray("updatedAts", Instant.class, updatedAts)
                .bindArray("startedAts", Instant.class, startedAts)
                .bindArray("completedAts", Instant.class, completedAts)
                .executeAndReturnGeneratedKeys("id")
                .mapTo(UUID.class)
                .list();
    }

    public @Nullable WorkflowRunMetadataRow getRunMetadataById(final UUID id) {
        final Query query = jdbiHandle.createQuery("""
                select *
                  from workflow_run
                 where id = :id
                """);

        return query
                .bind("id", id)
                .mapTo(WorkflowRunMetadataRow.class)
                .findOne()
                .orElse(null);
    }

    public Map<UUID, PolledWorkflowRun> pollAndLockRuns(
            final UUID workerInstanceId,
            final Collection<PollWorkflowTaskCommand> commands,
            final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                with cte_poll as (
                  select id
                    from workflow_run
                   where workflow_name = any(:workflowNames)
                     and status = any(cast('{CREATED, RUNNING, SUSPENDED}' as workflow_run_status[]))
                     and (concurrency_group_id is null
                          or exists (
                               select 1
                                 from workflow_run_concurrency_group as wrcg
                                where wrcg.id = workflow_run.concurrency_group_id
                                  and wrcg.next_run_id = workflow_run.id
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

        final var workflowNames = new ArrayList<String>(commands.size());
        final var lockTimeouts = new ArrayList<Duration>(commands.size());

        for (final PollWorkflowTaskCommand command : commands) {
            workflowNames.add(command.workflowName());
            lockTimeouts.add(command.lockTimeout());
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
                .mapTo(PolledWorkflowRun.class)
                .collectToMap(PolledWorkflowRun::id, Function.identity());
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

    public int createRunInboxEvents(final SequencedCollection<CreateWorkflowRunInboxEntryCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_run_inbox (
                  workflow_run_id
                , visible_from
                , event
                )
                select * from unnest(:runIds, :visibleFroms, :events)
                """);

        final var runIds = new ArrayList<UUID>(commands.size());
        final var visibleFroms = new ArrayList<@Nullable Instant>(commands.size());
        final var events = new ArrayList<Event>(commands.size());

        for (final CreateWorkflowRunInboxEntryCommand command : commands) {
            runIds.add(command.workflowRunId());
            visibleFroms.add(command.visibleFrom());
            events.add(command.event());
        }

        return update
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("visibleFroms", Instant.class, visibleFroms)
                .bindArray("events", Event.class, events)
                .execute();
    }

    public Map<UUID, PolledWorkflowEvents> pollRunEvents(
            final UUID workerInstanceId,
            final Collection<GetWorkflowRunHistoryRequest> requests) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_history as (
                    select workflow_run_history.workflow_run_id
                         , event
                         , sequence_number
                      from workflow_run_history
                     inner join unnest(:historyRequestRunIds, :historyRequestOffsets) as request(run_id, "offset")
                        on request.run_id = workflow_run_history.workflow_run_id
                       and request."offset" < workflow_run_history.sequence_number
                     order by sequence_number
                ),
                cte_inbox_poll_candidate as (
                    select id
                      from workflow_run_inbox
                     where workflow_run_id = any(:historyRequestRunIds)
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
                select 'HISTORY' as event_type
                     , workflow_run_id
                     , event
                     , sequence_number
                     , null as dequeue_count
                  from cte_history
                 union all
                select 'INBOX' as event_type
                     , workflow_run_id
                     , event
                     , null as sequence_number
                     , dequeue_count
                  from cte_polled_inbox
                """);

        final var historyRequestRunIds = new ArrayList<UUID>(requests.size());
        final var historyRequestOffsets = new ArrayList<Integer>(requests.size());

        for (final GetWorkflowRunHistoryRequest request : requests) {
            historyRequestRunIds.add(request.runId());
            historyRequestOffsets.add(request.offset());
        }

        final List<PolledWorkflowEvent> polledEvents = query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("historyRequestRunIds", UUID.class, historyRequestRunIds)
                .bindArray("historyRequestOffsets", Integer.class, historyRequestOffsets)
                .mapTo(PolledWorkflowEvent.class)
                .list();

        final var historyByRunId = new HashMap<UUID, List<Event>>(requests.size());
        final var inboxByRunId = new HashMap<UUID, List<Event>>(requests.size());
        final var maxHistoryEventSequenceNumberByRunId = new HashMap<UUID, Integer>(requests.size());
        final var maxInboxEventDequeueCountByRunId = new HashMap<UUID, Integer>(requests.size());

        for (final PolledWorkflowEvent polledEvent : polledEvents) {
            switch (polledEvent.eventType()) {
                case HISTORY -> {
                    historyByRunId.computeIfAbsent(
                            polledEvent.workflowRunId(), ignored -> new ArrayList<>()).add(polledEvent.event());

                    maxHistoryEventSequenceNumberByRunId.compute(
                            polledEvent.workflowRunId(),
                            (ignored, previousMax) -> (previousMax == null || previousMax < polledEvent.historySequenceNumber())
                                    ? polledEvent.historySequenceNumber()
                                    : previousMax);
                }
                case INBOX -> {
                    inboxByRunId.computeIfAbsent(
                            polledEvent.workflowRunId(), ignored -> new ArrayList<>()).add(polledEvent.event());

                    maxInboxEventDequeueCountByRunId.compute(
                            polledEvent.workflowRunId(),
                            (ignored, previousMax) -> (previousMax == null || previousMax < polledEvent.inboxDequeueCount())
                                    ? polledEvent.inboxDequeueCount()
                                    : previousMax);
                }
            }
        }

        final var polledEventsByRunId = new HashMap<UUID, PolledWorkflowEvents>(requests.size());
        for (final UUID runId : historyRequestRunIds) {
            polledEventsByRunId.put(runId, new PolledWorkflowEvents(
                    historyByRunId.getOrDefault(runId, Collections.emptyList()),
                    inboxByRunId.getOrDefault(runId, Collections.emptyList()),
                    maxHistoryEventSequenceNumberByRunId.getOrDefault(runId, -1),
                    maxInboxEventDequeueCountByRunId.getOrDefault(runId, 0)));
        }

        return polledEventsByRunId;
    }

    public List<Event> getRunInboxByRunId(final UUID runId) {
        final Query query = jdbiHandle.createQuery("""
                select event
                  from workflow_run_inbox
                 where workflow_run_id = :runId
                 order by id
                """);

        return query
                .bind("runId", runId)
                .mapTo(Event.class)
                .list();
    }

    public int unlockRunInboxEvents(
            final UUID workerInstanceId,
            final Collection<UnlockWorkflowRunInboxEventsCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_run_inbox
                   set locked_by = null
                     , visible_from = now() + t.visibility_delay
                  from unnest(:runIds, :visibilityDelays) as t(run_id, visibility_delay)
                 where workflow_run_id = t.run_id
                   and locked_by = :workerInstanceId
                """);

        final var runIds = new ArrayList<UUID>(commands.size());
        final var visibilityDelays = new ArrayList<Duration>(commands.size());

        for (final UnlockWorkflowRunInboxEventsCommand command : commands) {
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
            final Collection<DeleteInboxEventsCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                delete
                  from workflow_run_inbox
                 using unnest(:workflowRunIds, :onlyLockeds) as delete_command (workflow_run_id, only_locked)
                 where workflow_run_inbox.workflow_run_id = delete_command.workflow_run_id
                   and (not delete_command.only_locked
                         or workflow_run_inbox.locked_by = :workerInstanceId)
                """);

        final var runIds = new ArrayList<UUID>(commands.size());
        final var onlyLockeds = new ArrayList<Boolean>(commands.size());

        for (final DeleteInboxEventsCommand command : commands) {
            runIds.add(command.workflowRunId());
            onlyLockeds.add(command.onlyLocked());
        }

        return update
                .bindArray("workflowRunIds", UUID.class, runIds)
                .bindArray("onlyLockeds", Boolean.class, onlyLockeds)
                .bind("workerInstanceId", workerInstanceId.toString())
                .execute();
    }

    public int createRunHistoryEntries(final Collection<CreateWorkflowRunHistoryEntryCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_run_history (
                  workflow_run_id
                , sequence_number
                , event
                )
                select * from unnest(:runIds, :sequenceNumbers, :events)
                """);

        final var runIds = new ArrayList<UUID>(commands.size());
        final var sequenceNumbers = new ArrayList<Integer>(commands.size());
        final var events = new ArrayList<Event>(commands.size());

        for (final CreateWorkflowRunHistoryEntryCommand command : commands) {
            runIds.add(command.workflowRunId());
            sequenceNumbers.add(command.sequenceNumber());
            events.add(command.event());
        }

        return update
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("sequenceNumbers", Integer.class, sequenceNumbers)
                .bindArray("events", Event.class, events)
                .execute();
    }

    public int truncateRunHistories(final Collection<UUID> runIds) {
        final Update update = jdbiHandle.createUpdate("""
                delete from workflow_run_history
                 where workflow_run_id = any(:runIds)
                """);

        return update
                .bindArray("runIds", UUID.class, runIds)
                .execute();
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
