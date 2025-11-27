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
import org.dependencytrack.dex.engine.ActivityTaskId;
import org.dependencytrack.dex.engine.api.ActivityTaskQueue;
import org.dependencytrack.dex.engine.api.request.CreateActivityTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.ListActivityTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.UpdateActivityTaskQueueRequest;
import org.dependencytrack.dex.engine.persistence.command.CreateActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.PollActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.ScheduleActivityTaskRetryCommand;
import org.dependencytrack.dex.engine.persistence.model.PolledActivityTask;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class ActivityDao extends AbstractDao {

    public ActivityDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    public boolean createActivityTaskQueue(final CreateActivityTaskQueueRequest request) {
        return jdbiHandle
                .createQuery("""
                        select dex_create_activity_task_queue(:name, cast(:maxConcurrency as smallint))
                        """)
                .bindMethods(request)
                .mapTo(boolean.class)
                .one();
    }

    public boolean updateActivityTaskQueue(final UpdateActivityTaskQueueRequest request) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_queue as (
                  select name
                    from dex_activity_task_queue
                   where name = :name
                ),
                cte_updated_queue as (
                  update dex_activity_task_queue as queue
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

    public boolean doesActivityTaskQueueExists(final String name) {
        final Query query = jdbiHandle.createQuery("""
                select exists(
                  select 1
                    from dex_activity_task_queue
                   where name = :name
                )
                """);

        return query
                .bind("name", name)
                .mapTo(boolean.class)
                .one();
    }

    record ListActivityTaskQueuesPageToken(String lastName) implements PageToken {
    }

    public Page<ActivityTaskQueue> listActivityTaskQueues(final ListActivityTaskQueuesRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastName" type="boolean" -->
                select name
                     , status
                     , max_concurrency
                     , (
                         select count(*)
                           from dex_activity_task as task
                          where task.queue_name = queue.name
                            and task.status = 'QUEUED'
                       ) as depth
                     , created_at
                     , updated_at
                  from dex_activity_task_queue as queue
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

    public int createActivityTasks(final Collection<CreateActivityTaskCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into dex_activity_task (
                  workflow_run_id
                , created_event_id
                , activity_name
                , queue_name
                , priority
                , argument
                , retry_policy
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
                       , :retryPolicies
                       )
                """);

        final var runIds = new UUID[commands.size()];
        final var createdEventIds = new int[commands.size()];
        final var activityNames = new String[commands.size()];
        final var queueNames = new String[commands.size()];
        final var priorities = new int[commands.size()];
        final var arguments = new byte[commands.size()][];
        final var retryPolicies = new byte[commands.size()][];

        int i = 0;
        for (final CreateActivityTaskCommand command : commands) {
            runIds[i] = command.workflowRunId();
            createdEventIds[i] = command.createdEventId();
            activityNames[i] = command.activityName();
            queueNames[i] = command.queueName();
            priorities[i] = command.priority();
            arguments[i] = command.argument() != null
                    ? command.argument().toByteArray()
                    : null;
            retryPolicies[i] = command.retryPolicy().toByteArray();
            i++;
        }

        return update
                .bind("runIds", runIds)
                .bind("createdEventIds", createdEventIds)
                .bind("activityNames", activityNames)
                .bind("queueNames", queueNames)
                .bind("priorities", priorities)
                .bind("arguments", arguments)
                .bind("retryPolicies", retryPolicies)
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
                        , dat.retry_policy
                        , dat.attempt
                        , dat.locked_until
                """);

        final var activityNames = new String[commands.size()];
        final var lockTimeouts = new Duration[commands.size()];

        int i = 0;
        for (final PollActivityTaskCommand command : commands) {
            activityNames[i] = command.activityName();
            lockTimeouts[i] = command.lockTimeout();
            i++;
        }

        return query
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("queueName", queueName)
                .bind("activityNames", activityNames)
                .bind("lockTimeouts", lockTimeouts)
                .bind("limit", limit)
                .mapTo(PolledActivityTask.class)
                .list();
    }

    public int scheduleActivityTasksForRetry(
            final UUID workerInstanceId,
            final Collection<ScheduleActivityTaskRetryCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                with cte_cmd as (
                  select *
                    from unnest(:queueNames, :workflowRunIds, :createdEventIds, :retryAts)
                      as t(queue_name, workflow_run_id, created_event_id, retry_at)
                )
                update dex_activity_task as dat
                   set status = 'CREATED'
                     , attempt = attempt + 1
                     , visible_from = cte_cmd.retry_at
                     , locked_by = null
                     , locked_until = null
                     , updated_at = now()
                  from cte_cmd
                 where dat.queue_name = cte_cmd.queue_name
                   and dat.workflow_run_id = cte_cmd.workflow_run_id
                   and dat.created_event_id = cte_cmd.created_event_id
                   and dat.locked_by = :workerInstanceId
                """);

        final var queueNames = new String[commands.size()];
        final var workflowRunIds = new UUID[commands.size()];
        final var createdEventIds = new int[commands.size()];
        final var retryAts = new Instant[commands.size()];

        int i = 0;
        for (final ScheduleActivityTaskRetryCommand command : commands) {
            queueNames[i] = command.taskId().queueName();
            workflowRunIds[i] = command.taskId().workflowRunId();
            createdEventIds[i] = command.taskId().createdEventId();
            retryAts[i] = command.retryAt();
            i++;
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("queueNames", queueNames)
                .bind("workflowRunIds", workflowRunIds)
                .bind("createdEventIds", createdEventIds)
                .bind("retryAts", retryAts)
                .execute();
    }

    public int unlockActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var queueNames = new String[activityTasks.size()];
        final var workflowRunIds = new UUID[activityTasks.size()];
        final var createdEventIds = new int[activityTasks.size()];

        int i = 0;
        for (final ActivityTaskId activityTask : activityTasks) {
            queueNames[i] = activityTask.queueName();
            workflowRunIds[i] = activityTask.workflowRunId();
            createdEventIds[i] = activityTask.createdEventId();
            i++;
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
                .bind("queueNames", queueNames)
                .bind("workflowRunIds", workflowRunIds)
                .bind("createdEventIds", createdEventIds)
                .execute();
    }

    public int deleteLockedActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var queueNames = new String[activityTasks.size()];
        final var workflowRunIds = new UUID[activityTasks.size()];
        final var createdEventIds = new int[activityTasks.size()];

        int i = 0;
        for (final ActivityTaskId activityTask : activityTasks) {
            queueNames[i] = activityTask.queueName();
            workflowRunIds[i] = activityTask.workflowRunId();
            createdEventIds[i] = activityTask.createdEventId();
            i++;
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
                .bind("queueNames", queueNames)
                .bind("workflowRunIds", workflowRunIds)
                .bind("createdEventIds", createdEventIds)
                .execute();
    }

}
