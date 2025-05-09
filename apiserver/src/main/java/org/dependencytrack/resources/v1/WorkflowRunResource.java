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
package org.dependencytrack.resources.v1;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.resources.v1.vo.WorkflowRunListItem;
import org.dependencytrack.resources.v1.vo.WorkflowRunResponse;
import org.dependencytrack.workflow.engine.WorkflowEngine;
import org.dependencytrack.workflow.engine.WorkflowRunStateProjection;
import org.dependencytrack.workflow.engine.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.persistence.model.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.pagination.Page;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Link;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@Path("/v1/workflow/run")
@Tag(name = "workflowRun")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class WorkflowRunResource {

    private final WorkflowEngine workflowEngine;

    @Inject
    public WorkflowRunResource(final WorkflowEngine workflowEngine) {
        this.workflowEngine = workflowEngine;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    // TODO: @PermissionRequired()
    public Response getRuns(
            @Context UriInfo uriInfo,
            @QueryParam("workflowName") List<String> workflowNameFilter,
            @QueryParam("status") final List<WorkflowRunStatus> statusFilter,
            @QueryParam("pageToken") final String pageToken,
            @QueryParam("pageSize") final int pageSize) {
        final Page<WorkflowRunRow> runsPage = workflowEngine.listRuns(
                ListWorkflowRunsRequest.builder()
                        .nameFilter(workflowNameFilter)
                        .statusFilter(statusFilter)
                        .labelFilter(/* TODO */ null)
                        .pageToken(pageToken)
                        .limit(pageSize)
                        .build());

        final List<WorkflowRunListItem> listItems = runsPage.items().stream()
                .map(WorkflowRunListItem::of)
                .toList();

        final ResponseBuilder responseBuilder = Response.ok(listItems);
        if (runsPage.nextPageToken() != null) {
            final UriBuilder nextLinkUriBuilder = uriInfo.getAbsolutePathBuilder()
                    .queryParam("pageToken", runsPage.nextPageToken())
                    .queryParam("pageSize", pageSize > 0 ? String.valueOf(pageSize) : "100");
            if (workflowNameFilter != null) {
                for (final String workflowName : workflowNameFilter) {
                    nextLinkUriBuilder.queryParam("workflowName", workflowName);
                }
            }
            if (statusFilter != null) {
                for (final WorkflowRunStatus status : statusFilter) {
                    nextLinkUriBuilder.queryParam("status", status.name());
                }
            }

            responseBuilder.links(
                    Link.fromUriBuilder(nextLinkUriBuilder)
                            .rel("next")
                            .build());
        }

        return responseBuilder.build();
    }

    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    // TODO: @PermissionRequired()
    public Response getRun(@PathParam("id") final UUID id) {
        final WorkflowRunStateProjection stateProjection = workflowEngine.getRun(id);
        if (stateProjection == null) {
            throw new NoSuchElementException("Workflow run could not be found");
        }

        return Response.ok(WorkflowRunResponse.of(stateProjection)).build();
    }

}
