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

import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.pagination.Page;
import org.dependencytrack.dex.engine.api.pagination.SortDirection;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunMetadataRow;
import org.dependencytrack.dex.proto.event.v1.Event;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class WorkflowRunDao extends AbstractDao {

    public WorkflowRunDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    record ListRunsPageToken(
            UUID lastId,
            long lastCreatedAt,
            @Nullable Long lastCompletedAt,
            ListWorkflowRunsRequest.SortBy sortBy,
            SortDirection sortDirection) {
    }

    public Page<WorkflowRunMetadata> listRuns(final ListWorkflowRunsRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="completedAtFrom" type="boolean" -->
                <#-- @ftlvariable name="completedAtTo" type="boolean" -->
                <#-- @ftlvariable name="createdAtFrom" type="boolean" -->
                <#-- @ftlvariable name="createdAtTo" type="boolean" -->
                <#-- @ftlvariable name="labels" type="boolean" -->
                <#-- @ftlvariable name="lastCompletedAt" type="boolean" -->
                <#-- @ftlvariable name="lastCreatedAt" type="boolean" -->
                <#-- @ftlvariable name="lastId" type="boolean" -->
                <#-- @ftlvariable name="sortBy" type="org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest.SortBy" -->
                <#-- @ftlvariable name="sortDirection" type="org.dependencytrack.dex.engine.api.pagination.SortDirection" -->
                <#-- @ftlvariable name="status" type="boolean" -->
                <#-- @ftlvariable name="workflowName" type="boolean" -->
                <#-- @ftlvariable name="workflowVersion" type="boolean" -->
                select *
                  from dex_workflow_run
                 where true
                <#if workflowName>
                   and workflow_name = :workflowName
                </#if>
                <#if workflowVersion>
                   and workflow_version = :workflowVersion
                </#if>
                <#if status>
                   and status = :status
                </#if>
                <#if labels>
                   and labels @> cast(:labels as jsonb)
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
                <#if sortBy == 'CREATED_AT'>
                  <#if sortDirection == 'ASC'>
                    <#if lastCreatedAt && lastId>
                      and (created_at > :lastCreatedAt or (created_at = :lastCreatedAt and id > :lastId))
                    </#if>
                    order by created_at asc, id asc
                  <#else>
                    <#if lastCreatedAt && lastId>
                      and (created_at < :lastCreatedAt or (created_at = :lastCreatedAt and id < :lastId))
                    </#if>
                    order by created_at desc, id desc
                  </#if>
                <#elseif sortBy == 'COMPLETED_AT'>
                  <#if sortDirection == 'ASC'>
                    <#if lastCompletedAt && lastId>
                      and (completed_at > :lastCompletedAt or (completed_at = :lastCompletedAt and id > :lastId))
                    </#if>
                    order by completed_at asc nulls last, id asc nulls first
                  <#else>
                    <#if lastCompletedAt && lastId>
                      and (completed_at < :lastCompletedAt or (completed_at = :lastCompletedAt and id < :lastId))
                    </#if>
                    order by completed_at desc nulls first, id desc
                  </#if>
                <#else>
                  <#if sortDirection == 'ASC'>
                    <#if lastId>
                      and id > :lastId
                    </#if>
                    order by id
                  <#else>
                    <#if lastId>
                      and id < :lastId
                    </#if>
                    order by id desc
                  </#if>
                </#if>
                 limit :limit
                """);

        String labelsJson = null;
        if (request.labels() != null && !request.labels().isEmpty()) {
            final JsonMapper.TypedJsonMapper jsonMapper = jdbiHandle
                    .getConfig(JsonConfig.class).getJsonMapper()
                    .forType(new GenericType<Map<String, String>>() {
                    }.getType(), jdbiHandle.getConfig());
            labelsJson = jsonMapper.toJson(request.labels(), jdbiHandle.getConfig());
        }

        final var decodedPageToken = decodePageToken(request.pageToken(), ListRunsPageToken.class);

        Instant lastCompletedAt = null;
        Instant lastCreatedAt = null;
        ListWorkflowRunsRequest.SortBy sortBy;
        SortDirection sortDirection;

        if (decodedPageToken != null) {
            lastCompletedAt = decodedPageToken.lastCompletedAt() != null
                    ? Instant.ofEpochMilli(decodedPageToken.lastCompletedAt())
                    : null;
            lastCreatedAt = Instant.ofEpochMilli(decodedPageToken.lastCreatedAt());
            sortBy = decodedPageToken.sortBy();
            sortDirection = decodedPageToken.sortDirection();
        } else {
            sortBy = request.sortBy() == null
                    ? ListWorkflowRunsRequest.SortBy.ID
                    : request.sortBy();
            sortDirection = request.sortDirection() == null
                    ? SortDirection.DESC
                    : request.sortDirection();
        }

        final List<WorkflowRunMetadata> rows = query
                .bind("workflowName", request.workflowName())
                .bind("workflowVersion", request.workflowVersion())
                .bind("status", request.status())
                .bindByType("labels", labelsJson, String.class)
                .bind("createdAtFrom", request.createdAtFrom())
                .bind("createdAtTo", request.createdAtTo())
                .bind("completedAtFrom", request.completedAtFrom())
                .bind("completedAtTo", request.completedAtTo())
                .bind("limit", request.limit() + 1)
                .bind("lastCompletedAt", lastCompletedAt)
                .bind("lastCreatedAt", lastCreatedAt)
                .bind("lastId", decodedPageToken != null ? decodedPageToken.lastId() : null)
                .define("sortBy", sortBy)
                .define("sortDirection", sortDirection)
                .defineNamedBindings()
                .mapTo(WorkflowRunMetadataRow.class)
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
                ? new ListRunsPageToken(
                resultItems.getLast().id(),
                resultItems.getLast().createdAt().toEpochMilli(),
                resultItems.getLast().completedAt() != null
                        ? resultItems.getLast().completedAt().toEpochMilli()
                        : null,
                sortBy,
                sortDirection)
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken));
    }

    record ListRunHistoryPageToken(int lastSequenceNumber) {
    }

    public Page<Event> listRunEvents(final ListWorkflowRunEventsRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery("""
                select *
                  from dex_workflow_run_history
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
