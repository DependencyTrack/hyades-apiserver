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

import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;

@Path("/v1/workflow")
@Tag(name = "workflow")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class WorkflowResource extends AbstractApiResource {

    private final DexEngine dexEngine;

    @Inject
    WorkflowResource(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
    }

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
        final var token = UUID.fromString(uuid);

        final WorkflowRunMetadata runMetadata = dexEngine.getRunMetadataById(token);
        if (runMetadata != null) {
            if ("analyze-project".equals(runMetadata.workflowName())) {
                return Response
                        .ok(List.of(convert(runMetadata, WorkflowStep.VULN_ANALYSIS, token)))
                        .build();
            }
        }

        final Page<WorkflowRunMetadata> runsPage = dexEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withLabels(Map.of(WF_LABEL_BOM_UPLOAD_TOKEN, token.toString()))
                        .withLimit(10));

        if (!runsPage.items().isEmpty()) {
            final var workflowStates = new ArrayList<WorkflowState>();
            for (final WorkflowRunMetadata run : runsPage.items()) {
                switch (run.workflowName()) {
                    case "import-bom" -> addImportBomStates(workflowStates, run, token);
                    case "analyze-project" -> addAnalyzeProjectStates(workflowStates, run, token);
                }
            }

            return Response.ok(workflowStates).build();
        }

        try (final var qm = new QueryManager(getAlpineRequest())) {
            final List<WorkflowState> workflowStates = qm.getAllWorkflowStatesForAToken(token);
            if (workflowStates.isEmpty()) {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("Provided token " + token + " does not exist.").build();
            }
            return Response.ok(workflowStates).build();
        }
    }

    private static void addImportBomStates(List<WorkflowState> states, WorkflowRunMetadata run, UUID token) {
        final WorkflowStatus status = convert(run.status());

        states.add(createLegacyState(token, WorkflowStep.BOM_CONSUMPTION, status, run));
        states.add(createLegacyState(token, WorkflowStep.BOM_PROCESSING, status, run));
    }

    private static void addAnalyzeProjectStates(List<WorkflowState> states, WorkflowRunMetadata run, UUID token) {
        final WorkflowStatus status = convert(run.status());

        states.add(createLegacyState(token, WorkflowStep.VULN_ANALYSIS, status, run));
        states.add(createLegacyState(token, WorkflowStep.POLICY_EVALUATION, status, run));
        states.add(createLegacyState(token, WorkflowStep.METRICS_UPDATE, status, run));
    }

    private static WorkflowState convert(WorkflowRunMetadata run, WorkflowStep step, UUID token) {
        return createLegacyState(token, step, convert(run.status()), run);
    }

    private static WorkflowStatus convert(WorkflowRunStatus dexStatus) {
        return switch (dexStatus) {
            case CREATED, RUNNING, SUSPENDED -> WorkflowStatus.PENDING;
            case CANCELLED -> WorkflowStatus.CANCELLED;
            case COMPLETED -> WorkflowStatus.COMPLETED;
            case FAILED -> WorkflowStatus.FAILED;
        };
    }

    private static WorkflowState createLegacyState(
            UUID token,
            WorkflowStep step,
            WorkflowStatus status,
            WorkflowRunMetadata run) {
        final var state = new WorkflowState();
        state.setToken(token);
        state.setStep(step);
        state.setStatus(status);
        if (run.startedAt() != null) {
            state.setStartedAt(Date.from(run.startedAt()));
        }
        if (run.updatedAt() != null) {
            state.setUpdatedAt(Date.from(run.updatedAt()));
        }
        return state;
    }

}
