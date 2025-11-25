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
package org.dependencytrack.dex.engine.persistence;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.WorkflowTaskQueue;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.UpdateWorkflowTaskQueueRequest;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunHistoryEntryCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunInboxEntryCommand;
import org.dependencytrack.dex.engine.persistence.command.DeleteInboxEventsCommand;
import org.dependencytrack.dex.engine.persistence.command.PollWorkflowTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.UnlockWorkflowRunInboxEventsCommand;
import org.dependencytrack.dex.engine.persistence.command.UnlockWorkflowTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.UpdateAndUnlockRunCommand;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvent;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunMetadataRow;
import org.dependencytrack.dex.engine.persistence.request.GetWorkflowRunHistoryRequest;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.jdbi.v3.core.Handle;
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
import java.util.NoSuchElementException;
import java.util.SequencedCollection;
import java.util.UUID;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static org.jdbi.v3.core.generic.GenericTypes.parameterizeClass;

public final class WorkflowDao extends AbstractDao {

    public WorkflowDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    public boolean createWorkflowTaskQueue(final CreateWorkflowTaskQueueRequest request) {
        return jdbiHandle
                .createQuery("""
                        select dex_create_workflow_task_queue(:name, cast(:maxConcurrency as smallint))
                        """)
                .bindMethods(request)
                .mapTo(boolean.class)
                .one();
    }

    public boolean updateWorkflowTaskQueue(final UpdateWorkflowTaskQueueRequest request) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_queue as (
                  select name
                    from dex_workflow_task_queue
                   where name = :name
                ),
                cte_updated_queue as (
                  update dex_workflow_task_queue as queue
                     set status = coalesce(:status, queue.status)
                       , max_concurrency = coalesce(:maxConcurrency, queue.max_concurrency)
                   where queue.name = :name
                     and (queue.status != :status or queue.max_concurrency != :maxConcurrency)
                   returning 1
                )
                select exists(select 1 from cte_queue) as exists
                     , exists(select 1 from cte_updated_queue) as updated
                """);

        final Map.Entry<Boolean, Boolean> existsAndUpdated = query
                .bindMethods(request)
                .map((rs, ctx) -> Map.entry(rs.getBoolean(1), rs.getBoolean(2)))
                .one();

        final boolean exists = existsAndUpdated.getKey();
        final boolean updated = existsAndUpdated.getValue();

        if (!exists) {
            throw new NoSuchElementException();
        }

        return updated;
    }

    public boolean doesWorkflowTaskQueueExists(final String name) {
        final Query query = jdbiHandle.createQuery("""
                select exists(
                  select 1
                    from dex_workflow_task_queue
                   where name = :name
                )
                """);

        return query
                .bind("name", name)
                .mapTo(boolean.class)
                .one();
    }

    record ListWorkflowTaskQueuesPageToken(String lastName) implements PageToken {
    }

    public Page<WorkflowTaskQueue> listWorkflowTaskQueues(final ListWorkflowTaskQueuesRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastName" type="boolean" -->
                select name
                     , status
                     , max_concurrency
                     , (
                         select count(*)
                           from dex_workflow_task as task
                          where task.queue_name = queue.name
                       ) as depth
                     , created_at
                     , updated_at
                  from dex_workflow_task_queue as queue
                 where true
                <#if lastName>
                   and name > :lastName
                </#if>
                 order by name
                 limit :limit
                """);

        final var pageTokenValue = decodePageToken(request.pageToken(), ListWorkflowTaskQueuesPageToken.class);

        // Query for one additional row to determine if there are more results.
        final int limit = request.limit() > 0 ? request.limit() : 100;
        final int limitWithNext = limit + 1;

        final List<WorkflowTaskQueue> rows = query
                .bind("limit", limitWithNext)
                .bind("lastName", pageTokenValue != null ? pageTokenValue.lastName() : null)
                .defineNamedBindings()
                .mapTo(WorkflowTaskQueue.class)
                .list();

        final List<WorkflowTaskQueue> resultItems = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListWorkflowTaskQueuesPageToken nextPageToken = rows.size() == limitWithNext
                ? new ListWorkflowTaskQueuesPageToken(resultItems.getLast().name())
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken));
    }

    public Map<UUID, UUID> createRuns(final Collection<CreateWorkflowRunCommand> commands) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_cmd as (
                  select *
                    from unnest (
                      :requestIds
                    , :ids
                    , :parentIds
                    , :workflowNames
                    , :workflowVersions
                    , :queueNames
                    , :concurrencyGroupIds
                    , :concurrencyModes
                    , :priorities
                    , cast(:labelsJsons as jsonb[])
                    , :createdAts
                    ) as t (
                      request_id
                    , id
                    , parent_id
                    , workflow_name
                    , workflow_version
                    , queue_name
                    , concurrency_group_id
                    , concurrency_mode
                    , priority
                    , labels
                    , created_at
                    )
                ),
                cte_created as (
                  insert into dex_workflow_run (
                    id
                  , parent_id
                  , workflow_name
                  , workflow_version
                  , queue_name
                  , concurrency_group_id
                  , concurrency_mode
                  , priority
                  , labels
                  , created_at
                  )
                  select id
                       , parent_id
                       , workflow_name
                       , workflow_version
                       , queue_name
                       , concurrency_group_id
                       , concurrency_mode
                       , priority
                       , labels
                       , created_at
                    from cte_cmd
                  -- Index expression of dex_workflow_run_exclusive_concurrency_idx.
                  on conflict (concurrency_group_id)
                        where concurrency_group_id is not null
                          and concurrency_mode = 'EXCLUSIVE'
                          and status in ('CREATED', 'RUNNING', 'SUSPENDED')
                  do nothing
                  returning id
                )
                select cte_cmd.request_id as request_id
                     , cte_created.id as run_id
                  from cte_created
                 inner join cte_cmd
                    on cte_cmd.id = cte_created.id
                """);

        final var requestIds = new UUID[commands.size()];
        final var ids = new UUID[commands.size()];
        final var parentIds = new @Nullable UUID[commands.size()];
        final var workflowNames = new String[commands.size()];
        final var workflowVersions = new int[commands.size()];
        final var queueNames = new String[commands.size()];
        final var concurrencyGroupIds = new @Nullable String[commands.size()];
        final var concurrencyModes = new @Nullable String[commands.size()];
        final var priorities = new int[commands.size()];
        final var labelsJsons = new @Nullable String[commands.size()];
        final var createdAts = new Instant[commands.size()];

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class).getJsonMapper()
                .forType(parameterizeClass(Map.class, String.class, String.class), jdbiHandle.getConfig());

        int i = 0;
        for (final CreateWorkflowRunCommand command : commands) {
            final String labelsJson;
            if (command.labels() == null || command.labels().isEmpty()) {
                labelsJson = null;
            } else {
                labelsJson = jsonMapper.toJson(command.labels(), jdbiHandle.getConfig());
            }

            requestIds[i] = command.requestId();
            ids[i] = command.id();
            parentIds[i] = command.parentId();
            workflowNames[i] = command.workflowName();
            workflowVersions[i] = command.workflowVersion();
            queueNames[i] = command.queueName();
            concurrencyGroupIds[i] = command.concurrencyGroupId();
            concurrencyModes[i] = command.concurrencyMode() != null
                    ? command.concurrencyMode().name()
                    : null;
            priorities[i] = command.priority();
            labelsJsons[i] = labelsJson;
            createdAts[i] = command.createdAt();
            i++;
        }

        return query
                .bind("requestIds", requestIds)
                .bind("ids", ids)
                .bind("parentIds", parentIds)
                .bind("workflowNames", workflowNames)
                .bind("workflowVersions", workflowVersions)
                .bind("queueNames", queueNames)
                .bind("concurrencyGroupIds", concurrencyGroupIds)
                .bind("concurrencyModes", concurrencyModes)
                .bind("priorities", priorities)
                .bind("labelsJsons", labelsJsons)
                .bind("createdAts", createdAts)
                .map((rs, ctx) -> Map.entry(
                        rs.getObject("request_id", UUID.class),
                        rs.getObject("run_id", UUID.class)))
                .collectToMap(Map.Entry::getKey, Map.Entry::getValue);
    }

    public List<WorkflowRunCountByNameAndStatusRow> getRunCountByNameAndStatus() {
        final Query query = jdbiHandle.createQuery("""
                select workflow_name
                     , status
                     , count(*)
                  from dex_workflow_run
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
                with
                cte_command as (
                  select *
                    from unnest (:ids, :queueNames, :statuses, :customStatuses, :updatedAts, :startedAts, :completedAts)
                      as t(id, queue_name, status, custom_status, updated_at, started_at, completed_at)
                ),
                cte_deleted_task as (
                  delete
                    from dex_workflow_task as task
                   using cte_command
                   where task.queue_name = cte_command.queue_name
                     and task.workflow_run_id = cte_command.id
                     and task.locked_by = :workerInstanceId
                  returning task.workflow_run_id
                          , task.queue_name
                )
                update dex_workflow_run as run
                   set status = coalesce(cte_command.status, run.status)
                     , custom_status = coalesce(cte_command.custom_status, run.custom_status)
                     , updated_at = coalesce(cte_command.updated_at, run.updated_at)
                     , started_at = coalesce(cte_command.started_at, run.started_at)
                     , completed_at = coalesce(cte_command.completed_at, run.completed_at)
                  from cte_deleted_task
                 inner join cte_command
                    on cte_command.id = cte_deleted_task.workflow_run_id
                 where run.id = cte_deleted_task.workflow_run_id
                returning run.id
                """);

        final var ids = new UUID[commands.size()];
        final var queueNames = new String[commands.size()];
        final var statuses = new WorkflowRunStatus[commands.size()];
        final var customStatuses = new @Nullable String[commands.size()];
        final var updatedAts = new @Nullable Instant[commands.size()];
        final var startedAts = new @Nullable Instant[commands.size()];
        final var completedAts = new @Nullable Instant[commands.size()];

        int i = 0;
        for (final UpdateAndUnlockRunCommand command : commands) {
            ids[i] = command.id();
            queueNames[i] = command.queueName();
            statuses[i] = command.status();
            customStatuses[i] = command.customStatus();
            updatedAts[i] = command.updatedAt();
            startedAts[i] = command.startedAt();
            completedAts[i] = command.completedAt();
            i++;
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("ids", ids)
                .bind("queueNames", queueNames)
                .bind("statuses", statuses)
                .bind("customStatuses", customStatuses)
                .bind("updatedAts", updatedAts)
                .bind("startedAts", startedAts)
                .bind("completedAts", completedAts)
                .executeAndReturnGeneratedKeys()
                .mapTo(UUID.class)
                .list();
    }

    public @Nullable WorkflowRunMetadataRow getRunMetadataById(final UUID id) {
        final Query query = jdbiHandle.createQuery("""
                select *
                  from dex_workflow_run
                 where id = :id
                """);

        return query
                .bind("id", id)
                .mapTo(WorkflowRunMetadataRow.class)
                .findOne()
                .orElse(null);
    }

    public Map<UUID, PolledWorkflowTask> pollAndLockWorkflowTasks(
            final UUID workerInstanceId,
            final String queueName,
            final Collection<PollWorkflowTaskCommand> commands,
            final int limit) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_poll as (
                  select workflow_run_id
                    from dex_workflow_task as task
                   inner join dex_workflow_task_queue as queue
                      on queue.name = task.queue_name
                   where task.queue_name = :queueName
                     and queue.status = 'ACTIVE'
                     and (task.locked_until is null or task.locked_until <= now())
                   order by task.priority desc
                          , task.workflow_run_id
                     for no key update of task
                    skip locked
                   limit :limit
                ),
                cte_locked as (
                  update dex_workflow_task as task
                     set locked_by = :workerInstanceId
                       , locked_until = now() + (
                           select t.lock_timeout
                             from unnest(:workflowNames, :lockTimeouts) as t(workflow_name, lock_timeout)
                            where t.workflow_name = task.workflow_name
                            limit 1
                         )
                   from cte_poll
                  where task.queue_name = :queueName
                    and task.workflow_run_id = cte_poll.workflow_run_id
                  returning task.queue_name
                          , task.workflow_run_id
                )
                select run.id
                     , run.workflow_name
                     , run.workflow_version
                     , run.queue_name
                     , run.concurrency_group_id
                     , run.priority
                     , run.labels
                  from dex_workflow_run as run
                 inner join cte_locked
                    on cte_locked.queue_name = run.queue_name
                   and cte_locked.workflow_run_id = run.id
                """);

        final var workflowNames = new String[commands.size()];
        final var lockTimeouts = new Duration[commands.size()];

        int i = 0;
        for (final PollWorkflowTaskCommand command : commands) {
            workflowNames[i] = command.workflowName();
            lockTimeouts[i] = command.lockTimeout();
            i++;
        }

        return query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("queueName", queueName)
                .bind("workflowNames", workflowNames)
                .bind("lockTimeouts", lockTimeouts)
                .bind("limit", limit)
                .mapTo(PolledWorkflowTask.class)
                .collectToMap(PolledWorkflowTask::runId, Function.identity());
    }

    public int unlockWorkflowTasks(final UUID workerInstanceId, final Collection<UnlockWorkflowTaskCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                update dex_workflow_task as task
                   set locked_by = null
                     , locked_until = null
                  from unnest(:queueNames, :runIds)
                    as t(queue_name, run_id)
                 where task.queue_name = t.queue_name
                   and task.workflow_run_id = t.run_id
                   and task.locked_by = :workerInstanceId
                """);

        final var queueNames = new String[commands.size()];
        final var runIds = new UUID[commands.size()];

        int i = 0;
        for (final UnlockWorkflowTaskCommand command : commands) {
            queueNames[i] = command.queueName();
            runIds[i] = command.runId();
            i++;
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("queueNames", queueNames)
                .bindArray("runIds", runIds)
                .execute();
    }

    public int createRunInboxEvents(final SequencedCollection<CreateWorkflowRunInboxEntryCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into dex_workflow_run_inbox (
                  workflow_run_id
                , visible_from
                , event
                )
                select * from unnest(:runIds, :visibleFroms, :events)
                """);

        final var runIds = new UUID[commands.size()];
        final var visibleFroms = new @Nullable Instant[commands.size()];
        final var events = new byte[commands.size()][];

        int i = 0;
        for (final CreateWorkflowRunInboxEntryCommand command : commands) {
            runIds[i] = command.workflowRunId();
            visibleFroms[i] = command.visibleFrom();
            events[i] = command.event().toByteArray();
            i++;
        }

        return update
                .bind("runIds", runIds)
                .bind("visibleFroms", visibleFroms)
                .bind("events", events)
                .execute();
    }

    public Map<UUID, PolledWorkflowEvents> pollRunEvents(
            final UUID workerInstanceId,
            final Collection<GetWorkflowRunHistoryRequest> requests) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_history as (
                    select dex_workflow_run_history.workflow_run_id
                         , event
                         , sequence_number
                      from dex_workflow_run_history
                     inner join unnest(:historyRequestRunIds, :historyRequestOffsets) as request(run_id, "offset")
                        on request.run_id = dex_workflow_run_history.workflow_run_id
                       and request."offset" < dex_workflow_run_history.sequence_number
                     order by sequence_number
                ),
                cte_inbox_poll_candidate as (
                    select id
                      from dex_workflow_run_inbox
                     where workflow_run_id = any(:historyRequestRunIds)
                       and (visible_from is null or visible_from <= now())
                     order by id
                       for no key update
                      skip locked
                ),
                cte_polled_inbox as (
                    update dex_workflow_run_inbox
                       set locked_by = :workerInstanceId
                         , dequeue_count = coalesce(dequeue_count, 0) + 1
                      from cte_inbox_poll_candidate
                     where cte_inbox_poll_candidate.id = dex_workflow_run_inbox.id
                    returning dex_workflow_run_inbox.workflow_run_id
                            , dex_workflow_run_inbox.event
                            , dex_workflow_run_inbox.dequeue_count
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

        final var historyRequestRunIds = new UUID[requests.size()];
        final var historyRequestOffsets = new int[requests.size()];

        int i = 0;
        for (final GetWorkflowRunHistoryRequest request : requests) {
            historyRequestRunIds[i] = request.runId();
            historyRequestOffsets[i] = request.offset();
            i++;
        }

        final List<PolledWorkflowEvent> polledEvents = query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("historyRequestRunIds", historyRequestRunIds)
                .bind("historyRequestOffsets", historyRequestOffsets)
                .mapTo(PolledWorkflowEvent.class)
                .list();

        final var historyByRunId = new HashMap<UUID, List<WorkflowEvent>>(requests.size());
        final var inboxByRunId = new HashMap<UUID, List<WorkflowEvent>>(requests.size());
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

    public List<WorkflowEvent> getRunInboxByRunId(final UUID runId) {
        final Query query = jdbiHandle.createQuery("""
                select event
                  from dex_workflow_run_inbox
                 where workflow_run_id = :runId
                 order by id
                """);

        return query
                .bind("runId", runId)
                .mapTo(WorkflowEvent.class)
                .list();
    }

    public int unlockRunInboxEvents(
            final UUID workerInstanceId,
            final Collection<UnlockWorkflowRunInboxEventsCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                update dex_workflow_run_inbox
                   set locked_by = null
                     , visible_from = now() + t.visibility_delay
                  from unnest(:runIds, :visibilityDelays) as t(run_id, visibility_delay)
                 where workflow_run_id = t.run_id
                   and locked_by = :workerInstanceId
                """);

        final var runIds = new UUID[commands.size()];
        final var visibilityDelays = new Duration[commands.size()];

        int i = 0;
        for (final UnlockWorkflowRunInboxEventsCommand command : commands) {
            runIds[i] = command.workflowRunId();
            visibilityDelays[i] = command.visibilityDelay();
            i++;
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("runIds", runIds)
                .bind("visibilityDelays", visibilityDelays)
                .execute();
    }

    public int deleteRunInboxEvents(
            final UUID workerInstanceId,
            final Collection<DeleteInboxEventsCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                delete
                  from dex_workflow_run_inbox
                 using unnest(:workflowRunIds, :onlyLockeds) as delete_command (workflow_run_id, only_locked)
                 where dex_workflow_run_inbox.workflow_run_id = delete_command.workflow_run_id
                   and (not delete_command.only_locked
                         or dex_workflow_run_inbox.locked_by = :workerInstanceId)
                """);

        final var runIds = new UUID[commands.size()];
        final var onlyLockeds = new boolean[commands.size()];

        int i = 0;
        for (final DeleteInboxEventsCommand command : commands) {
            runIds[i] = command.workflowRunId();
            onlyLockeds[i] = command.onlyLocked();
            i++;
        }

        return update
                .bind("workflowRunIds", runIds)
                .bind("onlyLockeds", onlyLockeds)
                .bind("workerInstanceId", workerInstanceId.toString())
                .execute();
    }

    public int createRunHistoryEntries(final Collection<CreateWorkflowRunHistoryEntryCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into dex_workflow_run_history (
                  workflow_run_id
                , sequence_number
                , event
                )
                select * from unnest(:runIds, :sequenceNumbers, :events)
                """);

        final var runIds = new UUID[commands.size()];
        final var sequenceNumbers = new int[commands.size()];
        final var events = new byte[commands.size()][];

        int i = 0;
        for (final CreateWorkflowRunHistoryEntryCommand command : commands) {
            runIds[i] = command.workflowRunId();
            sequenceNumbers[i] = command.sequenceNumber();
            events[i] = command.event().toByteArray();
            i++;
        }

        return update
                .bind("runIds", runIds)
                .bind("sequenceNumbers", sequenceNumbers)
                .bind("events", events)
                .execute();
    }

    public int truncateRunHistories(final Collection<UUID> runIds) {
        final Update update = jdbiHandle.createUpdate("""
                delete
                  from dex_workflow_run_history
                 where workflow_run_id = any(:runIds)
                """);

        return update
                .bindArray("runIds", UUID.class, runIds)
                .execute();
    }

}
