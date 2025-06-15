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
import org.dependencytrack.workflow.engine.api.WorkflowSchedule;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowSchedulesRequest;
import org.dependencytrack.workflow.engine.persistence.model.NewWorkflowScheduleRow;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public final class WorkflowScheduleDao extends AbstractDao {

    public WorkflowScheduleDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    public List<WorkflowSchedule> createSchedules(final Collection<NewWorkflowScheduleRow> newSchedules) {
        final Update update = jdbiHandle.createUpdate("""
                insert into workflow_schedule (
                  name
                , cron
                , workflow_name
                , workflow_version
                , concurrency_group_id
                , priority
                , labels
                , argument
                , next_fire_at
                )
                select *
                  from unnest (
                         :names
                       , :crons
                       , :workflowNames
                       , :workflowVersions
                       , :concurrencyGroupIds
                       , :priorities
                       , cast(:labelsJsons as jsonb[])
                       , :arguments
                       , :nextFireAts
                       )
                on conflict (name) do nothing
                returning *
                """);

        final var names = new ArrayList<String>(newSchedules.size());
        final var crons = new ArrayList<String>(newSchedules.size());
        final var workflowNames = new ArrayList<String>(newSchedules.size());
        final var workflowVersions = new ArrayList<Integer>(newSchedules.size());
        final var concurrencyGroupIds = new ArrayList<String>(newSchedules.size());
        final var priorities = new ArrayList<Integer>(newSchedules.size());
        final var labelsJsons = new ArrayList<String>(newSchedules.size());
        final var arguments = new ArrayList<WorkflowPayload>(newSchedules.size());
        final var nextFireAts = new ArrayList<Instant>(newSchedules.size());

        final JsonMapper.TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class).getJsonMapper()
                .forType(new GenericType<Map<String, String>>() {
                }.getType(), jdbiHandle.getConfig());

        for (final NewWorkflowScheduleRow newSchedule : newSchedules) {
            final String labelsJson;
            if (newSchedule.labels() == null || newSchedule.labels().isEmpty()) {
                labelsJson = null;
            } else {
                labelsJson = jsonMapper.toJson(newSchedule.labels(), jdbiHandle.getConfig());
            }

            names.add(newSchedule.name());
            crons.add(newSchedule.cron());
            workflowNames.add(newSchedule.workflowName());
            workflowVersions.add(newSchedule.workflowVersion());
            concurrencyGroupIds.add(newSchedule.concurrencyGroupId());
            priorities.add(newSchedule.priority());
            labelsJsons.add(labelsJson);
            arguments.add(newSchedule.argument());
            nextFireAts.add(newSchedule.nextFireAt());
        }

        return update
                .bindArray("names", String.class, names)
                .bindArray("crons", String.class, crons)
                .bindArray("workflowNames", String.class, workflowNames)
                .bindArray("workflowVersions", Integer.class, workflowVersions)
                .bindArray("concurrencyGroupIds", String.class, concurrencyGroupIds)
                .bindArray("priorities", Integer.class, priorities)
                .bindArray("labelsJsons", String.class, labelsJsons)
                .bindArray("arguments", WorkflowPayload.class, arguments)
                .bindArray("nextFireAts", Instant.class, nextFireAts)
                .executeAndReturnGeneratedKeys("*")
                .mapTo(WorkflowSchedule.class)
                .list();
    }

    record ListSchedulesPageToken(String lastName) {
    }

    public Page<WorkflowSchedule> listSchedules(final ListWorkflowSchedulesRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastName" type="boolean" -->
                <#-- @ftlvariable name="workflowNameFilter" type="boolean" -->
                select *
                  from workflow_schedule
                 where true
                <#if lastName>
                   and name > :lastName
                </#if>
                <#if workflowNameFilter>
                   and workflow_name = :workflowNameFilter
                </#if>
                 order by name
                 limit :limit
                """);

        final var pageTokenValue = decodePageToken(request.pageToken(), ListSchedulesPageToken.class);

        // Query for one additional row to determine if there are more results.
        final int limit = request.limit() > 0 ? request.limit() : 100;
        final int limitWithNext = limit + 1;

        final List<WorkflowSchedule> rows = query
                .bind("workflowNameFilter", request.workflowNameFilter())
                .bind("limit", limitWithNext)
                .bind("lastName", pageTokenValue != null ? pageTokenValue.lastName() : null)
                .defineNamedBindings()
                .mapTo(WorkflowSchedule.class)
                .list();

        final List<WorkflowSchedule> resultItems = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListSchedulesPageToken nextPageToken = rows.size() == limitWithNext
                ? new ListSchedulesPageToken(resultItems.getLast().name())
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken));
    }

    public List<WorkflowSchedule> getDueSchedulesForUpdate() {
        final Query query = jdbiHandle.createQuery("""
                select *
                  from workflow_schedule
                 where next_fire_at <= now()
                 order by name
                   for no key update
                  skip locked
                """);

        return query
                .mapTo(WorkflowSchedule.class)
                .list();
    }

    public int updateScheduleNextFireAt(final Map<String, Instant> nextFireAtByName) {
        final var names = new ArrayList<String>(nextFireAtByName.size());
        final var nextFireAts = new ArrayList<Instant>(nextFireAtByName.size());

        for (final Map.Entry<String, Instant> entry : nextFireAtByName.entrySet()) {
            names.add(entry.getKey());
            nextFireAts.add(entry.getValue());
        }

        final Update update = jdbiHandle.createUpdate("""
                with params as (select * from unnest(:names, :nextFireAts) as t(name, next_fire_at))
                update workflow_schedule
                   set next_fire_at = params.next_fire_at
                     , updated_at = now()
                  from params
                 where params.name = workflow_schedule.name
                """);

        return update
                .bindArray("names", String.class, names)
                .bindArray("nextFireAts", Instant.class, nextFireAts)
                .execute();
    }

}
