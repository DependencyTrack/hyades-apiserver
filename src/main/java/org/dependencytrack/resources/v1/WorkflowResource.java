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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.resources.v1.serializers.WorkflowEventJsonSerializer;
import org.dependencytrack.workflow.WorkflowEngine;
import org.dependencytrack.workflow.WorkflowRunStatus;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunListRow;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;

import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@Path("/v1/workflow")
@Tag(name = "workflow")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class WorkflowResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(WorkflowResource.class);

    @GET
    @Path("/token/{uuid}/status")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Retrieves workflow states associated with the token received from bom upload .",
            description = "<p>Requires permission <strong>BOM_UPLOAD</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of workflow states",
                    content = @Content(schema = @Schema(implementation = WorkflowState.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "Workflow does not exist")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD) // TODO: Should be a more generic permission.
    public Response getWorkflowStates(
            @Parameter(description = "The UUID of the token to query", required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        List<WorkflowState> workflowStates;
        try (final var qm = new QueryManager()) {
            workflowStates = qm.getAllWorkflowStatesForAToken(UUID.fromString(uuid));
            if (workflowStates.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).entity("Provided token " + uuid + " does not exist.").build();
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred while fetching workflow status", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
        return Response.ok(workflowStates).build();
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record WorkflowRunListResponseItem(
            UUID id,
            String workflowName,
            int workflowVersion,
            String status,
            WorkflowRunStatus runtimeStatus,
            String concurrencyGroupId,
            Integer priority,
            Set<String> tags,
            @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant createdAt,
            @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant updatedAt,
            @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant startedAt,
            @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant completedAt,
            int historySize,
            int pendingEvents,
            int pendingActivities) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record WorkflowRunStats(Map<String, Map<WorkflowRunStatus, Long>> statuses) {
    }

    @GET
    @Path("/run/stats")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired // TODO
    public Response getWorkflowRunStats() {
        return withJdbiHandle(handle -> {
            final var dao = new WorkflowDao(handle);

            final Map<String, Map<WorkflowRunStatus, Long>> statusesByName =
                    dao.getWorkflowRunCountByNameAndStatus().stream()
                            .collect(Collectors.groupingBy(
                                    WorkflowRunCountByNameAndStatusRow::workflowName,
                                    Collectors.toMap(
                                            WorkflowRunCountByNameAndStatusRow::status,
                                            WorkflowRunCountByNameAndStatusRow::count)));

            final var stats = new WorkflowRunStats(statusesByName);
            return Response.ok(stats).build();
        });
    }

    @GET
    @Path("/run")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired // TODO
    public Response getWorkflowRuns(
            @QueryParam("workflowName") final String workflowNameFilter,
            @QueryParam("status") final WorkflowRunStatus statusFilter,
            @QueryParam("concurrencyGroupId") final String concurrencyGroupIdFilter) {
        assertWorkflowEngineEnabled();

        return withJdbiHandle(getAlpineRequest(), handle -> getWorkflowRunsInternal(
                new WorkflowDao(handle),
                workflowNameFilter,
                statusFilter,
                concurrencyGroupIdFilter,
                /* tagsFilter */ null));
    }

    @GET
    @Path("/run/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired // TODO
    public Response getWorkflowRunsForProject(
            @PathParam("uuid") @ValidUuid final String projectUuid,
            @QueryParam("workflowName") final String workflowNameFilter,
            @QueryParam("status") final WorkflowRunStatus statusFilter,
            @QueryParam("concurrencyGroupId") final String concurrencyGroupIdFilter) {
        assertWorkflowEngineEnabled();

        return withJdbiHandle(handle -> {
            final var projectDao = handle.attach(ProjectDao.class);
            final Boolean isProjectAccessible = projectDao.isAccessible(UUID.fromString(projectUuid));
            if (isProjectAccessible == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            } else if (!isProjectAccessible) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }

            final var workflowDao = new WorkflowDao(handle);
            return getWorkflowRunsInternal(
                    workflowDao,
                    workflowNameFilter,
                    statusFilter,
                    concurrencyGroupIdFilter,
                    Set.of("project=" + projectUuid));
        });
    }

    private Response getWorkflowRunsInternal(
            final WorkflowDao dao,
            final String workflowNameFilter,
            final WorkflowRunStatus statusFilter,
            final String concurrencyGroupIdFilter,
            final Set<String> tagsFilter) {
        final List<WorkflowRunListRow> runRows = dao.getWorkflowRuns(
                        workflowNameFilter,
                        statusFilter,
                        concurrencyGroupIdFilter,
                        tagsFilter);
        final List<WorkflowRunListResponseItem> responseItems = runRows.stream()
                .map(runRow -> new WorkflowRunListResponseItem(
                        runRow.id(),
                        runRow.workflowName(),
                        runRow.workflowVersion(),
                        runRow.customStatus(),
                        runRow.status(),
                        runRow.concurrencyGroupId(),
                        runRow.priority(),
                        runRow.tags(),
                        runRow.createdAt(),
                        runRow.updatedAt(),
                        runRow.startedAt(),
                        runRow.completedAt(),
                        runRow.historySize(),
                        runRow.pendingEvents(),
                        runRow.pendingActivities()))
                .toList();

        final long totalCount = runRows.isEmpty() ? 0 : runRows.getFirst().totalCount();
        return Response.ok(responseItems).header(TOTAL_COUNT_HEADER, totalCount).build();
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record WorkflowRunResponse(
            UUID id,
            String workflowName,
            int workflowVersion,
            String status,
            WorkflowRunStatus runtimeStatus,
            Integer priority,
            Set<String> tags,
            String lockedBy,
            Instant lockedUntil,
            @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant createdAt,
            @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant updatedAt,
            @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant completedAt,
            @JsonSerialize(contentUsing = WorkflowEventJsonSerializer.class) List<WorkflowEvent> eventLog,
            @JsonSerialize(contentUsing = WorkflowEventJsonSerializer.class) List<WorkflowEvent> eventInbox) {
    }

    @GET
    @Path("/run/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired // TODO
    public Response getWorkflowRun(@PathParam("id") @ValidUuid final String runId) {
        assertWorkflowEngineEnabled();

        final WorkflowRunResponse run = withJdbiHandle(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunRow runRow = dao.getWorkflowRun(UUID.fromString(runId));
            if (runRow == null) {
                throw new ClientErrorException(Response.Status.NOT_FOUND);
            }

            final List<WorkflowEvent> eventLog = dao.getWorkflowRunEventLog(UUID.fromString(runId));
            final List<WorkflowEvent> eventInbox = dao.getInboxEvents(UUID.fromString(runId));

            return new WorkflowRunResponse(
                    runRow.id(),
                    runRow.workflowName(),
                    runRow.workflowVersion(),
                    runRow.customStatus(),
                    runRow.status(),
                    runRow.priority(),
                    runRow.tags(),
                    runRow.lockedBy(),
                    runRow.lockedUntil(),
                    runRow.createdAt(),
                    runRow.updatedAt(),
                    runRow.completedAt(),
                    eventLog,
                    eventInbox);
        });

        return Response.ok(run).build();
    }

    @POST
    @Path("/run/{id}/cancel")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired // TODO
    public Response cancelWorkflowRun(
            @PathParam("id") @ValidUuid final String runId,
            @QueryParam("reason") @NotBlank final String reason) {
        assertWorkflowEngineEnabled();

        WorkflowEngine.getInstance().cancelWorkflowRun(UUID.fromString(runId), reason);
        return Response.noContent().build();
    }

    @POST
    @Path("/run/{id}/suspend")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired // TODO
    public Response suspendWorkflowRun(@PathParam("id") @ValidUuid final String runId) {
        assertWorkflowEngineEnabled();

        WorkflowEngine.getInstance().suspendWorkflowRun(UUID.fromString(runId));
        return Response.noContent().build();
    }

    @POST
    @Path("/run/{id}/resume")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired // TODO
    public Response resumeWorkflowRun(@PathParam("id") @ValidUuid final String runId) {
        assertWorkflowEngineEnabled();

        WorkflowEngine.getInstance().resumeWorkflowRun(UUID.fromString(runId));
        return Response.noContent().build();
    }

    private void assertWorkflowEngineEnabled() {
        if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_ENABLED)) {
            throw new ClientErrorException(Response.Status.NOT_FOUND);
        }
    }

}
