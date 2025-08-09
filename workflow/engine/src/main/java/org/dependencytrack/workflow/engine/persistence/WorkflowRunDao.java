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

import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.workflow.engine.api.WorkflowRunMetadata;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRun;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunHistoryEntry;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class WorkflowRunDao extends AbstractDao {

    public WorkflowRunDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    record ListRunsPageToken(UUID lastId) {
    }

    public Page<WorkflowRunMetadata> listRuns(final ListWorkflowRunsRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastId" type="boolean" -->
                <#-- @ftlvariable name="workflowNameFilter" type="boolean" -->
                <#-- @ftlvariable name="workflowVersionFilter" type="boolean" -->
                <#-- @ftlvariable name="statusFilter" type="boolean" -->
                <#-- @ftlvariable name="labelFilter" type="boolean" -->
                <#-- @ftlvariable name="createdAtFrom" type="boolean" -->
                <#-- @ftlvariable name="createdAtTo" type="boolean" -->
                <#-- @ftlvariable name="completedAtFrom" type="boolean" -->
                <#-- @ftlvariable name="completedAtTo" type="boolean" -->
                select *
                  from workflow_run
                 where true
                <#if lastId>
                   and id < :lastId
                </#if>
                <#if workflowNameFilter>
                   and workflow_name = :workflowNameFilter
                </#if>
                <#if workflowVersionFilter>
                   and workflow_version = :workflowVersionFilter
                </#if>
                <#if statusFilter>
                   and status = :statusFilter
                </#if>
                <#if labelFilter>
                   and labels @> cast(:labelFilter as jsonb)
                </#if>
                <#if createdAtFrom>
                   and created_at >= :createdAtFrom
                </#if>
                <#if createdAtTo>
                   and created_at < :createdAtTo
                </#if>
                <#if completedAtFrom>
                   and completed_at >= :completedAtFrom
                </#if>
                <#if completedAtTo>
                   and completed_at < :completedAtTo
                </#if>
                 order by id desc
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

        final var decodedPageToken = decodePageToken(request.pageToken(), ListRunsPageToken.class);

        final List<WorkflowRunMetadata> rows = query
                .bind("workflowNameFilter", request.workflowNameFilter())
                .bind("workflowVersionFilter", request.workflowVersionFilter())
                .bind("statusFilter", request.statusFilter())
                .bindByType("labelFilter", labelsJson, String.class)
                .bind("createdAtFrom", request.createdAtFrom())
                .bind("createdAtTo", request.createdAtTo())
                .bind("completedAtFrom", request.completedAtFrom())
                .bind("completedAtTo", request.completedAtTo())
                .bind("limit", request.limit() + 1)
                .bind("lastId", decodedPageToken != null ? decodedPageToken.lastId() : null)
                .defineNamedBindings()
                .mapTo(WorkflowRun.class)
                .map(row -> new WorkflowRunMetadata(
                        row.id(),
                        row.workflowName(),
                        row.workflowVersion(),
                        row.status(),
                        row.customStatus(),
                        row.priority(),
                        row.concurrencyGroupId(),
                        row.labels(),
                        row.createdAt(),
                        row.updatedAt(),
                        row.startedAt(),
                        row.completedAt()))
                .list();

        final List<WorkflowRunMetadata> resultItems = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), request.limit()))
                : rows;

        final ListRunsPageToken nextPageToken = rows.size() == (request.limit() + 1)
                ? new ListRunsPageToken(resultItems.getLast().id())
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken));
    }

    record ListRunHistoryPageToken(int lastSequenceNumber) {
    }

    public Page<WorkflowEvent> listRunEvents(final ListWorkflowRunEventsRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery("""
                select *
                  from workflow_run_history
                 where workflow_run_id = :runId
                   and sequence_number > :lastSequenceNumber
                 order by sequence_number
                 limit :limit
                """);

        final var decodedPageToken = decodePageToken(request.pageToken(), ListRunHistoryPageToken.class);

        final List<WorkflowRunHistoryEntry> rows = query
                .bind("runId", request.runId())
                .bind("lastSequenceNumber", decodedPageToken != null ? decodedPageToken.lastSequenceNumber() : -1)
                .bind("limit", request.limit() + 1)
                .mapTo(WorkflowRunHistoryEntry.class)
                .list();

        final List<WorkflowRunHistoryEntry> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), request.limit()))
                : rows;

        final ListRunHistoryPageToken nextPageToken = rows.size() == (request.limit() + 1)
                ? new ListRunHistoryPageToken(resultRows.getLast().sequenceNumber())
                : null;

        return new Page<>(
                resultRows.stream().map(WorkflowRunHistoryEntry::event).toList(),
                encodePageToken(nextPageToken));
    }

}
