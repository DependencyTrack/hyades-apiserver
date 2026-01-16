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
import jakarta.inject.Inject;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.WorkflowsApi;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponseItem;
import org.dependencytrack.api.v2.model.SortDirection;
import org.dependencytrack.api.v2.model.WorkflowRunStatus;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.resources.AbstractApiResource;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

@Path("/")
@NullMarked
public class WorkflowsResource extends AbstractApiResource implements WorkflowsApi {

    private final DexEngine dexEngine;

    @Inject
    WorkflowsResource(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
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
                        .withSortDirection(switch (sortDirection) {
                            case ASC -> org.dependencytrack.common.pagination.SortDirection.ASC;
                            case DESC -> org.dependencytrack.common.pagination.SortDirection.DESC;
                            case null -> null;
                        })
                        .withPageToken(pageToken)
                        .withLimit(limit));

        final var response = ListWorkflowRunsResponse.builder()
                .workflowRuns(runsPage.items().stream()
                        .<ListWorkflowRunsResponseItem>map(
                                runMetadata -> ListWorkflowRunsResponseItem.builder()
                                        .id(runMetadata.id())
                                        .workflowName(runMetadata.workflowName())
                                        .workflowVersion(runMetadata.workflowVersion())
                                        .workflowInstanceId(runMetadata.workflowInstanceId())
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
                                        .build())
                        .toList())
                .pagination(createPaginationMetadata(getUriInfo(), runsPage))
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

}
