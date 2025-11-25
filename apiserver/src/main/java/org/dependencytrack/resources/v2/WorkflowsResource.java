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

import alpine.server.auth.AuthenticationNotRequired;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.dependencytrack.api.v2.WorkflowsApi;
import org.dependencytrack.api.v2.model.ListWorkflowRunEventsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponseItem;
import org.dependencytrack.api.v2.model.SortDirection;
import org.dependencytrack.api.v2.model.WorkflowRunStatus;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.resources.AbstractApiResource;
import org.jspecify.annotations.NonNull;

import java.time.Instant;
import java.util.UUID;

@Path("/")
public class WorkflowsResource extends AbstractApiResource implements WorkflowsApi {

    @Context
    private UriInfo uriInfo;

    @Inject
    private DexEngine dexEngine;

    @Override
    @AuthenticationNotRequired // TODO
    public Response listWorkflowRuns(
            final String workflowName,
            final Integer workflowVersion,
            final WorkflowRunStatus status,
            final Long createdAtFrom,
            final Long createdAtTo,
            final Long completedAtFrom,
            final Long completedAtTo,
            final Integer limit,
            final String pageToken,
            final SortDirection sortDirection,
            final String sortBy) {
        if (dexEngine == null) {
            throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE);
        }

        final Page<@NonNull WorkflowRunMetadata> runsPage = dexEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withWorkflowName(workflowName)
                        .withWorkflowVersion(workflowVersion)
                        .withStatus(switch (status) {
                            case CANCELLED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.CANCELED;
                            case COMPLETED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.COMPLETED;
                            case FAILED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.FAILED;
                            case CREATED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.CREATED;
                            case RUNNING -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.RUNNING;
                            case SUSPENDED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.SUSPENDED;
                            case null -> null;
                        })
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
                        .withLimit(limit)
                        .withPageToken(pageToken));

        final var response = ListWorkflowRunsResponse.builder()
                .workflowRuns(runsPage.items().stream()
                        .<ListWorkflowRunsResponseItem>map(
                                runMetadata -> ListWorkflowRunsResponseItem.builder()
                                        .id(runMetadata.id())
                                        .workflowName(runMetadata.workflowName())
                                        .workflowVersion(runMetadata.workflowVersion())
                                        .status(switch (runMetadata.status()) {
                                            case CANCELED -> WorkflowRunStatus.CANCELLED;
                                            case COMPLETED -> WorkflowRunStatus.COMPLETED;
                                            case FAILED -> WorkflowRunStatus.FAILED;
                                            case CREATED -> WorkflowRunStatus.CREATED;
                                            case RUNNING -> WorkflowRunStatus.RUNNING;
                                            case SUSPENDED -> WorkflowRunStatus.SUSPENDED;
                                        })
                                        .priority(runMetadata.priority())
                                        .concurrencyGroupId(runMetadata.concurrencyGroupId())
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
                .pagination(createPaginationMetadata(uriInfo, runsPage))
                .build();

        return Response.ok(response).build();
    }

    @Override
    public Response listWorkflowRunEvents(final UUID runId, final Integer limit, final String pageToken) {
        if (dexEngine == null) {
            throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE);
        }

        final WorkflowRunMetadata runMetadata = dexEngine.getRunMetadata(runId);
        if (runMetadata == null) {
            throw new NotFoundException();
        }

        final Page<@NonNull WorkflowEvent> eventsPage = dexEngine.listRunEvents(
                new ListWorkflowRunEventsRequest(runId)
                        .withLimit(limit)
                        .withPageToken(pageToken));

        final var response = ListWorkflowRunEventsResponse.builder()
                .events(eventsPage.items().stream()
                        .map(event -> (Object) event)
                        .toList())
                .pagination(createPaginationMetadata(uriInfo, eventsPage))
                .build();

        return Response.ok(response).build();
    }

}
