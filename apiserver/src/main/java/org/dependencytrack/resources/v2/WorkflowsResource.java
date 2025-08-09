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
import alpine.server.auth.PermissionRequired;
import org.dependencytrack.api.v2.WorkflowsApi;
import org.dependencytrack.api.v2.model.ListWorkflowRunEventsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponseItem;
import org.dependencytrack.api.v2.model.ListWorkflowStatesResponse;
import org.dependencytrack.api.v2.model.ListWorkflowStatesResponseItem;
import org.dependencytrack.api.v2.model.PaginationLinks;
import org.dependencytrack.api.v2.model.PaginationMetadata;
import org.dependencytrack.api.v2.model.WorkflowRunStatus;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowRunMetadata;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;

import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Provider
public class WorkflowsResource implements WorkflowsApi {

    @Context
    private UriInfo uriInfo;

    private final WorkflowEngine workflowEngine;

    @Inject
    WorkflowsResource(final WorkflowEngine workflowEngine) {
        this.workflowEngine = workflowEngine;
    }

    @Override
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response getWorkflowStates(final UUID token) {
        List<WorkflowState> workflowStates;
        try (final var qm = new QueryManager()) {
            workflowStates = qm.getAllWorkflowStatesForAToken(token);
            if (workflowStates.isEmpty()) {
                throw new NotFoundException();
            }
        }
        List<ListWorkflowStatesResponseItem> states = workflowStates.stream()
                .map(this::mapWorkflowStateResponse)
                .collect(Collectors.toList());
        return Response.ok(ListWorkflowStatesResponse.builder().states(states).build()).build();
    }

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

        final Page<WorkflowRunMetadata> runsPage = workflowEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withWorkflowNameFilter(workflowName)
                        .withWorkflowVersionFilter(workflowVersion)
                        .withStatusFilter(switch (status) {
                            case CANCELLED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.CANCELED;
                            case COMPLETED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.COMPLETED;
                            case FAILED -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.FAILED;
                            case PENDING -> org.dependencytrack.workflow.engine.api.WorkflowRunStatus.PENDING;
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
                                            case PENDING -> WorkflowRunStatus.PENDING;
                                            case RUNNING -> WorkflowRunStatus.RUNNING;
                                            case SUSPENDED -> WorkflowRunStatus.SUSPENDED;
                                        })
                                        .priority(runMetadata.priority())
                                        .concurrencyGroupId(runMetadata.concurrencyGroupId())
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

        final Page<WorkflowEvent> eventsPage = workflowEngine.listRunEvents(
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

    private ListWorkflowStatesResponseItem mapWorkflowStateResponse(WorkflowState workflowState) {
        var mappedState = ListWorkflowStatesResponseItem.builder()
                .token(workflowState.getToken())
                .status(ListWorkflowStatesResponseItem.StatusEnum.fromString(workflowState.getStatus().name()))
                .step(ListWorkflowStatesResponseItem.StepEnum.fromString(workflowState.getStep().name()))
                .failureReason(workflowState.getFailureReason())
                .build();
        if (workflowState.getStartedAt() != null) {
            mappedState.setStartedAt(workflowState.getStartedAt().getTime());
        }
        if (workflowState.getUpdatedAt() != null) {
            mappedState.setUpdatedAt(workflowState.getUpdatedAt().getTime());
        }
        return mappedState;
    }
}
