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

import org.dependencytrack.dex.engine.api.ActivityTaskQueue;
import org.dependencytrack.dex.engine.api.TaskQueueStatus;
import org.dependencytrack.dex.engine.api.pagination.Page;
import org.dependencytrack.dex.engine.api.request.ListActivityTaskQueuesRequest;
import org.dependencytrack.dex.engine.persistence.command.CreateActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.PollActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.model.ActivityTaskId;
import org.dependencytrack.dex.engine.persistence.model.PolledActivityTask;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class ActivityDao extends AbstractDao {

    public ActivityDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    record ListActivityTaskQueuesPageToken(String lastName) {
    }

    public Page<ActivityTaskQueue> listActivityTaskQueues(final ListActivityTaskQueuesRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastName" type="boolean" -->
                select name
                     , status
                     , (
                         select count(*)
                           from dex_activity_task
                          where queue_name = dex_activity_task_queue.name
                            and status = 'QUEUED'
                       ) as depth
                     , created_at
                     , updated_at
                  from dex_activity_task_queue
                 where true
                <#if lastName>
                   and name > :lastName
                </#if>
                 order by name
                 limit :limit
                """);

        final var pageTokenValue = decodePageToken(request.pageToken(), ListActivityTaskQueuesPageToken.class);

        // Query for one additional row to determine if there are more results.
        final int limit = request.limit() > 0 ? request.limit() : 100;
        final int limitWithNext = limit + 1;

        final List<ActivityTaskQueue> rows = query
                .bind("limit", limitWithNext)
                .bind("lastName", pageTokenValue != null ? pageTokenValue.lastName() : null)
                .defineNamedBindings()
                .mapTo(ActivityTaskQueue.class)
                .list();

        final List<ActivityTaskQueue> resultItems = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListActivityTaskQueuesPageToken nextPageToken = rows.size() == limitWithNext
                ? new ListActivityTaskQueuesPageToken(resultItems.getLast().name())
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken));
    }

    public boolean setActivityTaskQueueStatus(final String queueName, final TaskQueueStatus status) {
        requireNonNull(queueName, "queueName must not be null");

        final Update update = jdbiHandle.createUpdate("""
                update dex_activity_task_queue
                   set status = :newStatus
                     , updated_at = now()
                 where name = :queueName
                   and status != :newStatus
                """);

        return update
                .bind("queueName", queueName)
                .bind("newStatus", status)
                .execute() > 0;
    }

    public int createActivityTasks(final Collection<CreateActivityTaskCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into dex_activity_task (
                  workflow_run_id
                , created_event_id
                , activity_name
                , queue_name
                , priority
                , argument
                , visible_from
                , created_at
                )
                select *
                     , now()
                  from unnest (
                         :runIds
                       , :createdEventIds
                       , :activityNames
                       , :queueNames
                       , :priorities
                       , :arguments
                       , :visibleFroms
                       )
                """);

        final var runIds = new ArrayList<UUID>(commands.size());
        final var createdEventIds = new ArrayList<Integer>(commands.size());
        final var activityNames = new ArrayList<String>(commands.size());
        final var queueNames = new ArrayList<String>(commands.size());
        final var priorities = new ArrayList<@Nullable Integer>(commands.size());
        final var arguments = new ArrayList<@Nullable Payload>(commands.size());
        final var visibleFroms = new ArrayList<@Nullable Instant>(commands.size());

        for (final CreateActivityTaskCommand command : commands) {
            runIds.add(command.workflowRunId());
            createdEventIds.add(command.createdEventId());
            activityNames.add(command.activityName());
            queueNames.add(command.queueName());
            priorities.add(command.priority());
            arguments.add(command.argument());
            visibleFroms.add(command.visibleFrom());
        }

        return update
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("createdEventIds", Integer.class, createdEventIds)
                .bindArray("activityNames", String.class, activityNames)
                .bindArray("queueNames", String.class, queueNames)
                .bindArray("priorities", Integer.class, priorities)
                .bindArray("arguments", Payload.class, arguments)
                .bindArray("visibleFroms", Instant.class, visibleFroms)
                .execute();
    }

    public List<PolledActivityTask> pollAndLockActivityTasks(
            final UUID workerInstanceId,
            final String queueName,
            final Collection<PollActivityTaskCommand> commands,
            final int limit) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_poll_req as (
                  select *
                    from unnest(:activityNames, :lockTimeouts)
                      as t(activity_name, lock_timeout)
                ),
                cte_poll as (
                  select workflow_run_id
                       , created_event_id
                       , activity_name
                    from dex_activity_task as dat
                   inner join dex_activity_task_queue as queue
                      on queue.name = dat.queue_name
                   where dat.queue_name = :queueName
                     and queue.status = 'ACTIVE'
                     and dat.status = 'QUEUED'
                     and (dat.locked_until is null or dat.locked_until <= now())
                   order by dat.priority desc
                          , dat.created_at
                     for no key update of dat skip locked
                   limit :limit
                )
                update dex_activity_task as dat
                   set locked_by = :workerInstanceId
                     , locked_until = now() + cte_poll_req.lock_timeout
                     , updated_at = now()
                  from cte_poll
                 inner join cte_poll_req
                    on cte_poll_req.activity_name = cte_poll.activity_name
                 where dat.queue_name = :queueName
                   and dat.workflow_run_id = cte_poll.workflow_run_id
                   and dat.created_event_id = cte_poll.created_event_id
                returning dat.workflow_run_id
                        , dat.created_event_id
                        , dat.activity_name
                        , dat.queue_name
                        , dat.priority
                        , dat.argument
                        , dat.locked_until
                """);

        final var activityNames = new ArrayList<String>(commands.size());
        final var lockTimeouts = new ArrayList<Duration>(commands.size());

        for (final PollActivityTaskCommand command : commands) {
            activityNames.add(command.activityName());
            lockTimeouts.add(command.lockTimeout());
        }

        return query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("queueName", queueName)
                .bindArray("activityNames", String.class, activityNames)
                .bindArray("lockTimeouts", Duration.class, lockTimeouts)
                .bind("limit", limit)
                .mapTo(PolledActivityTask.class)
                .list();
    }

    public @Nullable Instant extendActivityTaskLock(
            final UUID workerInstanceId,
            final ActivityTaskId activityTask,
            final Duration lockTimeout) {
        final Update update = jdbiHandle.createUpdate("""
                update dex_activity_task
                   set locked_until = locked_until + :lockTimeout
                     , updated_at = now()
                 where queue_name = :queueName
                   and workflow_run_id = :workflowRunId
                   and created_event_id = :createdEventId
                   and locked_by = :workerInstanceId
                returning locked_until
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("queueName", activityTask.queueName())
                .bind("workflowRunId", activityTask.workflowRunId())
                .bind("createdEventId", activityTask.createdEventId())
                .bind("lockTimeout", lockTimeout)
                .executeAndReturnGeneratedKeys("locked_until")
                .mapTo(Instant.class)
                .findOne()
                .orElse(null);
    }

    public int unlockActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var queueNames = new ArrayList<String>(activityTasks.size());
        final var workflowRunIds = new ArrayList<UUID>(activityTasks.size());
        final var createdEventIds = new ArrayList<Integer>(activityTasks.size());

        for (final ActivityTaskId activityTask : activityTasks) {
            queueNames.add(activityTask.queueName());
            workflowRunIds.add(activityTask.workflowRunId());
            createdEventIds.add(activityTask.createdEventId());
        }

        final Update update = jdbiHandle.createUpdate("""
                with cte as (
                  select *
                    from unnest(:queueNames, :workflowRunIds, :createdEventIds)
                      as t(queue_name, workflow_run_id, created_event_id)
                )
                update dex_activity_task as dat
                   set locked_by = null
                     , locked_until = null
                     , updated_at = now()
                  from cte
                 where cte.workflow_run_id = dat.workflow_run_id
                   and cte.created_event_id = dat.created_event_id
                   and dat.queue_name = cte.queue_name
                   and dat.locked_by = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("queueNames", String.class, queueNames)
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bindArray("createdEventIds", Integer.class, createdEventIds)
                .execute();
    }

    public int deleteLockedActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var queueNames = new ArrayList<String>(activityTasks.size());
        final var workflowRunIds = new ArrayList<UUID>(activityTasks.size());
        final var createdEventIds = new ArrayList<Integer>(activityTasks.size());

        for (final ActivityTaskId activityTask : activityTasks) {
            queueNames.add(activityTask.queueName());
            workflowRunIds.add(activityTask.workflowRunId());
            createdEventIds.add(activityTask.createdEventId());
        }

        final Update update = jdbiHandle.createUpdate("""
                with
                cte_req as (
                  select *
                    from unnest(:queueNames, :workflowRunIds, :createdEventIds)
                      as t(queue_name, workflow_run_id, created_event_id)
                )
                delete
                  from dex_activity_task as dat
                 using cte_req
                 where cte_req.workflow_run_id = dat.workflow_run_id
                   and cte_req.created_event_id = dat.created_event_id
                   and dat.queue_name = cte_req.queue_name
                   and dat.locked_by = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("queueNames", String.class, queueNames)
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bindArray("createdEventIds", Integer.class, createdEventIds)
                .execute();
    }

}
