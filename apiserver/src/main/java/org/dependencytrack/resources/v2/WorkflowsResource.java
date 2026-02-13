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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.util.JsonFormat;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.WorkflowsApi;
import org.dependencytrack.api.v2.model.ListWorkflowRunEventsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunEventsResponseItem;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponse;
import org.dependencytrack.api.v2.model.SortDirection;
import org.dependencytrack.api.v2.model.WorkflowRunStatus;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskCompleted;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskFailed;
import org.dependencytrack.dex.proto.event.v1.ChildRunCompleted;
import org.dependencytrack.dex.proto.event.v1.ChildRunFailed;
import org.dependencytrack.dex.proto.event.v1.TimerElapsed;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentCommon;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentCsaf;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentNotification;
import org.dependencytrack.resources.AbstractApiResource;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Path("/")
@NullMarked
public class WorkflowsResource extends AbstractApiResource implements WorkflowsApi {

    private final DexEngine dexEngine;
    private final ObjectMapper objectMapper;
    private final JsonFormat.Printer eventJsonPrinter;

    @Inject
    WorkflowsResource(DexEngine dexEngine, ObjectMapper objectMapper) {
        this.dexEngine = dexEngine;
        this.objectMapper = objectMapper;
        this.eventJsonPrinter = JsonFormat.printer()
                // Ensure that event IDs with value 0 are not omitted.
                .includingDefaultValueFields(Set.of(
                        WorkflowEvent.getDescriptor().findFieldByName("id"),
                        ActivityTaskCompleted.getDescriptor().findFieldByName("activity_task_created_event_id"),
                        ActivityTaskFailed.getDescriptor().findFieldByName("activity_task_created_event_id"),
                        ChildRunCompleted.getDescriptor().findFieldByName("child_run_created_event_id"),
                        ChildRunFailed.getDescriptor().findFieldByName("child_run_created_event_id"),
                        TimerElapsed.getDescriptor().findFieldByName("timer_created_event_id")))
                // Register message types that are used in Any fields.
                .usingTypeRegistry(
                        JsonFormat.TypeRegistry.newBuilder()
                                .add(ArgumentCommon.getDescriptor().getMessageTypes())
                                .add(ArgumentCsaf.getDescriptor().getMessageTypes())
                                .add(ArgumentNotification.getDescriptor().getMessageTypes())
                                .build());
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getWorkflowInstance(String id) {
        final WorkflowRunMetadata runMetadata = dexEngine.getRunMetadataByInstanceId(id);
        if (runMetadata == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(runMetadata)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listWorkflowRuns(
            @Nullable String workflowName,
            @Nullable Integer workflowVersion,
            @Nullable String workflowInstanceId,
            @Nullable WorkflowRunStatus status,
            @Nullable Long createdAtFrom,
            @Nullable Long createdAtTo,
            @Nullable Long completedAtFrom,
            @Nullable Long completedAtTo,
            Integer limit,
            @Nullable String pageToken,
            @Nullable SortDirection sortDirection,
            @Nullable String sortBy) {
        final Page<WorkflowRunMetadata> runsPage = dexEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withWorkflowName(workflowName)
                        .withWorkflowVersion(workflowVersion)
                        .withWorkflowInstanceId(workflowInstanceId)
                        .withStatus(convert(status))
                        .withCreatedAtFrom(createdAtFrom != null
                                ? Instant.ofEpochMilli(createdAtFrom)
                                : null)
                        .withCreatedAtTo(createdAtTo != null
                                ? Instant.ofEpochMilli(createdAtTo)
                                : null)
                        .withCompletedAtFrom(completedAtFrom != null
                                ? Instant.ofEpochMilli(completedAtFrom)
                                : null)
                        .withCompletedAtTo(completedAtTo != null
                                ? Instant.ofEpochMilli(completedAtTo)
                                : null)
                        .withSortBy(switch (sortBy) {
                            case "id" -> ListWorkflowRunsRequest.SortBy.ID;
                            case "created_at" -> ListWorkflowRunsRequest.SortBy.CREATED_AT;
                            case "completed_at" -> ListWorkflowRunsRequest.SortBy.COMPLETED_AT;
                            case null, default -> null;
                        })
                        .withSortDirection(convert(sortDirection))
                        .withPageToken(pageToken)
                        .withLimit(limit));

        final var response = ListWorkflowRunsResponse.builder()
                .workflowRuns(runsPage.items().stream()
                        .map(WorkflowsResource::convert)
                        .toList())
                .pagination(createPaginationMetadata(getUriInfo(), runsPage))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getWorkflowRun(UUID id) {
        final WorkflowRunMetadata runMetadata = dexEngine.getRunMetadataById(id);
        if (runMetadata == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(runMetadata)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listWorkflowRunEvents(
            UUID id,
            @Nullable Integer fromSequenceNumber,
            Integer limit,
            @Nullable String pageToken,
            @Nullable SortDirection sortDirection) {
        final Page<WorkflowRunHistoryEntry> historyEntryPage =
                dexEngine.listRunHistory(
                        new ListWorkflowRunHistoryRequest(id)
                                .withFromSequenceNumber(fromSequenceNumber)
                                .withSortDirection(convert(sortDirection))
                                .withPageToken(pageToken)
                                .withLimit(limit));

        final var response = ListWorkflowRunEventsResponse.builder()
                .events(historyEntryPage.items().stream()
                        .map(entry -> convert(entry, eventJsonPrinter, objectMapper))
                        .toList())
                .pagination(createPaginationMetadata(getUriInfo(), historyEntryPage))
                .build();

        return Response.ok(response).build();
    }

    private static org.dependencytrack.dex.engine.api.@Nullable WorkflowRunStatus convert(@Nullable WorkflowRunStatus status) {
        return switch (status) {
            case CANCELLED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.CANCELLED;
            case COMPLETED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.COMPLETED;
            case FAILED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.FAILED;
            case CREATED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.CREATED;
            case RUNNING -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.RUNNING;
            case SUSPENDED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.SUSPENDED;
            case null -> null;
        };
    }

    private static WorkflowRunStatus convert(org.dependencytrack.dex.engine.api.WorkflowRunStatus status) {
        return switch (status) {
            case CANCELLED -> WorkflowRunStatus.CANCELLED;
            case COMPLETED -> WorkflowRunStatus.COMPLETED;
            case FAILED -> WorkflowRunStatus.FAILED;
            case CREATED -> WorkflowRunStatus.CREATED;
            case RUNNING -> WorkflowRunStatus.RUNNING;
            case SUSPENDED -> WorkflowRunStatus.SUSPENDED;
        };
    }

    private static org.dependencytrack.api.v2.model.WorkflowRunMetadata convert(WorkflowRunMetadata runMetadata) {
        return org.dependencytrack.api.v2.model.WorkflowRunMetadata.builder()
                .id(runMetadata.id())
                .workflowName(runMetadata.workflowName())
                .workflowVersion(runMetadata.workflowVersion())
                .workflowInstanceId(runMetadata.workflowInstanceId())
                .taskQueueName(runMetadata.taskQueueName())
                .status(convert(runMetadata.status()))
                .priority(runMetadata.priority())
                .concurrencyKey(runMetadata.concurrencyKey())
                .labels(runMetadata.labels())
                .createdAt(runMetadata.createdAt().toEpochMilli())
                .updatedAt(runMetadata.updatedAt() != null
                        ? runMetadata.updatedAt().toEpochMilli()
                        : null)
                .startedAt(runMetadata.startedAt() != null
                        ? runMetadata.startedAt().toEpochMilli()
                        : null)
                .completedAt(runMetadata.completedAt() != null
                        ? runMetadata.completedAt().toEpochMilli()
                        : null)
                .build();
    }

    private static ListWorkflowRunEventsResponseItem convert(
            WorkflowRunHistoryEntry entry,
            JsonFormat.Printer eventJsonPrinter,
            ObjectMapper objectMapper) {
        final Map<String, Object> eventJsonMap;
        try {
            final String eventJson = eventJsonPrinter.print(entry.event());
            eventJsonMap = objectMapper.readValue(eventJson, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return ListWorkflowRunEventsResponseItem.builder()
                .sequenceNumber(entry.sequenceNumber())
                .event(eventJsonMap)
                .build();
    }

    private static org.dependencytrack.common.pagination.@Nullable SortDirection convert(
            @Nullable SortDirection sortDirection) {
        return switch (sortDirection) {
            case ASC -> org.dependencytrack.common.pagination.SortDirection.ASC;
            case DESC -> org.dependencytrack.common.pagination.SortDirection.DESC;
            case null -> null;
        };
    }

}
