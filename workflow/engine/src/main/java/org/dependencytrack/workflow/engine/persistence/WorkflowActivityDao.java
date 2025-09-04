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

import org.dependencytrack.proto.workflow.payload.v1.Payload;
import org.dependencytrack.workflow.engine.persistence.command.CreateActivityRunCommand;
import org.dependencytrack.workflow.engine.persistence.command.PollActivityTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.engine.persistence.model.PolledActivityTask;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

public final class WorkflowActivityDao extends AbstractDao {

    public WorkflowActivityDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    public int createActivityRuns(final Collection<CreateActivityRunCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_activity_run (
                  workflow_run_id
                , created_event_id
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
                       , :createdEventIds
                       , :activityNames
                       , :priorities
                       , :arguments
                       , :visibleFroms)
                """);

        final var runIds = new ArrayList<UUID>(commands.size());
        final var createdEventIds = new ArrayList<Integer>(commands.size());
        final var activityNames = new ArrayList<String>(commands.size());
        final var priorities = new ArrayList<@Nullable Integer>(commands.size());
        final var arguments = new ArrayList<@Nullable Payload>(commands.size());
        final var visibleFroms = new ArrayList<@Nullable Instant>(commands.size());

        for (final CreateActivityRunCommand command : commands) {
            runIds.add(command.workflowRunId());
            createdEventIds.add(command.createdEventId());
            activityNames.add(command.activityName());
            priorities.add(command.priority());
            arguments.add(command.argument());
            visibleFroms.add(command.visibleFrom());
        }

        return update
                .bindArray("runIds", UUID.class, runIds)
                .bindArray("createdEventIds", Integer.class, createdEventIds)
                .bindArray("activityNames", String.class, activityNames)
                .bindArray("priorities", Integer.class, priorities)
                .bindArray("arguments", Payload.class, arguments)
                .bindArray("visibleFroms", Instant.class, visibleFroms)
                .execute();
    }

    public List<PolledActivityTask> pollAndLockActivityTasks(
            final UUID workerInstanceId,
            final Collection<PollActivityTaskCommand> commands,
            final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                with
                cte_poll_req as (
                    select *
                      from unnest(:activityNames, :lockTimeouts) as t(activity_name, lock_timeout)
                ),
                cte_poll as (
                    select workflow_run_id
                         , created_event_id
                      from workflow_activity_run
                     where activity_name in (select activity_name from cte_poll_req)
                       and (visible_from is null or visible_from <= now())
                       and (locked_until is null or locked_until <= now())
                     order by priority desc nulls last
                            , created_at
                       for no key update
                      skip locked
                     limit :limit)
                update workflow_activity_run as war
                   set locked_by = :workerInstanceId
                     , locked_until = now() + cte_poll_req.lock_timeout
                     , updated_at = now()
                  from cte_poll
                     , cte_poll_req
                 where cte_poll.workflow_run_id = war.workflow_run_id
                   and cte_poll.created_event_id = war.created_event_id
                   and cte_poll_req.activity_name = war.activity_name
                returning war.workflow_run_id
                        , war.created_event_id
                        , war.activity_name
                        , war.priority
                        , war.argument
                        , war.locked_until
                """);

        final var activityNames = new ArrayList<String>(commands.size());
        final var lockTimeouts = new ArrayList<Duration>(commands.size());

        for (final PollActivityTaskCommand command : commands) {
            activityNames.add(command.activityName());
            lockTimeouts.add(command.lockTimeout());
        }

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("activityNames", String.class, activityNames)
                .bindArray("lockTimeouts", Duration.class, lockTimeouts)
                .bind("limit", limit)
                .executeAndReturnGeneratedKeys(
                        "workflow_run_id",
                        "created_event_id",
                        "activity_name",
                        "priority",
                        "argument",
                        "locked_until")
                .mapTo(PolledActivityTask.class)
                .list();
    }

    @Nullable
    public Instant extendActivityTaskLock(
            final UUID workerInstanceId,
            final ActivityTaskId activityTask,
            final Duration lockTimeout) {
        final Update update = jdbiHandle.createUpdate("""
                update workflow_activity_run
                   set locked_until = locked_until + :lockTimeout
                     , updated_at = now()
                 where workflow_run_id = :workflowRunId
                   and created_event_id = :createdEventId
                   and locked_by = :workerInstanceId
                returning locked_until
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bind("workflowRunId", activityTask.workflowRunId())
                .bind("createdEventId", activityTask.createdEventId())
                .bind("lockTimeout", lockTimeout)
                .executeAndReturnGeneratedKeys("locked_until")
                .mapTo(Instant.class)
                .findOne()
                .orElse(null);
    }

    public int unlockActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var workflowRunIds = new ArrayList<UUID>(activityTasks.size());
        final var createdEventIds = new ArrayList<Integer>(activityTasks.size());

        for (final ActivityTaskId activityTask : activityTasks) {
            workflowRunIds.add(activityTask.workflowRunId());
            createdEventIds.add(activityTask.createdEventId());
        }

        final Update update = jdbiHandle.createUpdate("""
                with cte as (
                    select *
                      from unnest(:workflowRunIds, :createdEventIds) as t(workflow_run_id, created_event_id))
                update workflow_activity_run
                   set locked_by = null
                     , locked_until = null
                  from cte
                 where cte.workflow_run_id = workflow_activity_run.workflow_run_id
                   and cte.created_event_id = workflow_activity_run.created_event_id
                   and workflow_activity_run.locked_by = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bindArray("createdEventIds", Integer.class, createdEventIds)
                .execute();
    }

    public int deleteLockedActivityTasks(final UUID workerInstanceId, final List<ActivityTaskId> activityTasks) {
        final var workflowRunIds = new ArrayList<UUID>(activityTasks.size());
        final var createdEventIds = new ArrayList<Integer>(activityTasks.size());

        for (final ActivityTaskId activityTask : activityTasks) {
            workflowRunIds.add(activityTask.workflowRunId());
            createdEventIds.add(activityTask.createdEventId());
        }

        final Update update = jdbiHandle.createUpdate("""
                with cte as (
                    select *
                      from unnest(:workflowRunIds, :createdEventIds) as t(workflow_run_id, created_event_id))
                delete
                  from workflow_activity_run
                 using cte
                 where cte.workflow_run_id = workflow_activity_run.workflow_run_id
                   and cte.created_event_id = workflow_activity_run.created_event_id
                   and workflow_activity_run.locked_by = :workerInstanceId
                """);

        return update
                .bind("workerInstanceId", workerInstanceId.toString())
                .bindArray("workflowRunIds", UUID.class, workflowRunIds)
                .bindArray("createdEventIds", Integer.class, createdEventIds)
                .execute();
    }

}
