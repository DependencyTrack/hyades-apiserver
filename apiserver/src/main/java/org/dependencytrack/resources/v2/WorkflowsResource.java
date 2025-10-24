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
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.WorkflowsApi;
import org.dependencytrack.api.v2.model.ListWorkflowRunEventsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponseItem;
import org.dependencytrack.api.v2.model.PaginationLinks;
import org.dependencytrack.api.v2.model.PaginationMetadata;
import org.dependencytrack.api.v2.model.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowRunMetadata;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.proto.event.v1.Event;
import org.jspecify.annotations.NonNull;

import java.util.UUID;

@Provider
public class WorkflowsResource implements WorkflowsApi {

    @Context
    private UriInfo uriInfo;

    @Inject
    private WorkflowEngine workflowEngine;

    @Override
    @AuthenticationNotRequired // TODO
    public Response listWorkflowRuns(
            final String workflowName,
            final Integer workflowVersion,
            final WorkflowRunStatus status,
            final Integer limit,
            final String pageToken) {
        if (workflowEngine == null) {
            throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE);
        }

        final Page<@NonNull WorkflowRunMetadata> runsPage = workflowEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withWorkflowName(workflowName)
                        .withWorkflowVersion(workflowVersion)
                        .withStatus(switch (status) {
                            case CANCELLED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.CANCELED;
                            case COMPLETED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.COMPLETED;
                            case FAILED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.FAILED;
                            case CREATED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.CREATED;
                            case RUNNING -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.RUNNING;
                            case SUSPENDED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.SUSPENDED;
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
                .pagination(PaginationMetadata.builder()
                        .links(PaginationLinks.builder()
                                .self(uriInfo.getRequestUri())
                                .next(runsPage.nextPageToken() != null
                                        ? uriInfo.getRequestUriBuilder()
                                        .queryParam("page_token", runsPage.nextPageToken())
                                        .build()
                                        : null)
                                .build())
                        .build())
                .build();

        return Response.ok(response).build();
    }

    @Override
    public Response listWorkflowRunEvents(final UUID runId, final Integer limit, final String pageToken) {
        if (workflowEngine == null) {
            throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE);
        }

        final WorkflowRunMetadata runMetadata = workflowEngine.getRunMetadata(runId);
        if (runMetadata == null) {
            throw new NotFoundException();
        }

        final Page<@NonNull Event> eventsPage = workflowEngine.listRunEvents(
                new ListWorkflowRunEventsRequest(runId)
                        .withLimit(limit)
                        .withPageToken(pageToken));

        final var response = ListWorkflowRunEventsResponse.builder()
                .events(eventsPage.items().stream()
                        .map(event -> (Object) event)
                        .toList())
                .pagination(PaginationMetadata.builder()
                        .links(PaginationLinks.builder()
                                .self(uriInfo.getRequestUri())
                                .next(eventsPage.nextPageToken() != null
                                        ? uriInfo.getRequestUriBuilder()
                                        .queryParam("page_token", eventsPage.nextPageToken())
                                        .build()
                                        : null)
                                .build())
                        .build())
                .build();

        return Response.ok(response).build();
    }

}
