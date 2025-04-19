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

import org.dependencytrack.workflow.engine.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.persistence.model.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.pagination.Page;
import org.dependencytrack.workflow.engine.proto.v1.ListWorkflowRunsPageToken;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.workflow.engine.persistence.pagination.PageTokenUtil.decodePageToken;
import static org.dependencytrack.workflow.engine.persistence.pagination.PageTokenUtil.encodePageToken;

public final class WorkflowRunDao {

    private final Handle jdbiHandle;

    public WorkflowRunDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public Page<WorkflowRunRow> listRuns(final ListWorkflowRunsRequest request) {
        requireNonNull(request, "request must not be null");

        final var pageTokenValue = decodePageToken(
                request.pageToken(), ListWorkflowRunsPageToken.parser());

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastId" type="boolean" -->
                <#-- @ftlvariable name="nameFilter" type="boolean" -->
                <#-- @ftlvariable name="statusFilter" type="boolean" -->
                <#-- @ftlvariable name="labelFilter" type="boolean" -->
                select *
                  from workflow_run
                 where true
                <#if lastId>
                   and id > :lastId
                </#if>
                <#if nameFilter>
                   and workflow_name = any(:nameFilter)
                </#if>
                <#if statusFilter>
                   and status = any(:statusFilter)
                </#if>
                <#if labelFilter>
                   and labels @> cast(:labelFilter as jsonb)
                </#if>
                 order by id
                 limit :limit
                """);

        String labelsJson = null;
        if (request.labelFilter() != null && !request.labelFilter().isEmpty()) {
            final JsonMapper.TypedJsonMapper jsonMapper = jdbiHandle
                    .getConfig(JsonConfig.class).getJsonMapper()
                    .forType(new GenericType<Map<String, String>>() {
                    }.getType(), jdbiHandle.getConfig());
            labelsJson = jsonMapper.toJson(request.labelFilter(), jdbiHandle.getConfig());
        }

        // Query for one additional row to determine if there are more results.
        final int limit = request.limit() > 0 ? request.limit() : 100;
        final int limitWithNext = limit + 1;

        final List<WorkflowRunRow> rows = query
                .bindArray("nameFilter", String.class, request.nameFilter())
                .bindArray("statusFilter", WorkflowRunStatus.class, request.statusFilter())
                .bindByType("labelFilter", labelsJson, String.class)
                .bind("limit", limitWithNext)
                .bind("lastId", pageTokenValue != null ? UUID.fromString(pageTokenValue.getLastId()) : null)
                .defineNamedBindings()
                .mapTo(WorkflowRunRow.class)
                .list();

        final List<WorkflowRunRow> resultItems = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListWorkflowRunsPageToken nextPageToken = rows.size() == limitWithNext
                ? ListWorkflowRunsPageToken.newBuilder().setLastId(resultItems.getLast().id().toString()).build()
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken));
    }

}
