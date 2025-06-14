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

import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;
import org.dependencytrack.workflow.engine.persistence.model.ActivityTaskId;
import org.dependencytrack.workflow.engine.persistence.model.NewActivityTaskRow;
import org.dependencytrack.workflow.engine.persistence.model.PollActivityTaskCommand;
import org.dependencytrack.workflow.engine.persistence.model.PolledActivityTaskRow;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

public final class WorkflowActivityDao {

    private final Handle jdbiHandle;

    public WorkflowActivityDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
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
            final Collection<PollActivityTaskCommand> pollCommands,
            final int limit) {
        final Update update = jdbiHandle.createUpdate("""
                with
                cte_poll_cmd as (
                    select *
                      from unnest(:activityNames, :lockTimeouts) as t(activity_name, lock_timeout)
                ),
                cte_poll as (
                    select workflow_run_id
                         , scheduled_event_id
                      from workflow_activity_task
                     where activity_name in (select activity_name from cte_poll_cmd)
                       and (visible_from is null or visible_from <= now())
                       and (locked_until is null or locked_until <= now())
                     order by priority desc nulls last
                            , created_at
                       for no key update
                      skip locked
                     limit :limit)
                update workflow_activity_task as wat
                   set locked_by = :workerInstanceId
                     , locked_until = now() + cte_poll_cmd.lock_timeout
                     , updated_at = now()
                  from cte_poll
                     , cte_poll_cmd
                 where cte_poll.workflow_run_id = wat.workflow_run_id
                   and cte_poll.scheduled_event_id = wat.scheduled_event_id
                   and cte_poll_cmd.activity_name = wat.activity_name
                returning wat.workflow_run_id
                        , wat.scheduled_event_id
                        , wat.activity_name
                        , wat.priority
                        , wat.argument
                        , wat.locked_until
                """);

        final var activityNames = new ArrayList<String>(pollCommands.size());
        final var lockTimeouts = new ArrayList<Duration>(pollCommands.size());

        for (final PollActivityTaskCommand command : pollCommands) {
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
                        "scheduled_event_id",
                        "activity_name",
                        "priority",
                        "argument",
                        "locked_until")
                .mapTo(PolledActivityTaskRow.class)
                .list();
    }

    @Nullable
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
