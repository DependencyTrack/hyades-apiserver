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

import alpine.common.logging.Logger;
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
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;

import java.util.List;
import java.util.UUID;

@Path("/v1/workflow")
@Tag(name = "workflow")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class WorkflowResource {

    private static final Logger LOGGER = Logger.getLogger(WorkflowResource.class);

    @Context
    private UriInfo uriInfo;

    @Inject
    private DexEngine dexEngine;

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
        if (dexEngine != null) {
            final WorkflowRunMetadata runMetadata =
                    dexEngine.getRunMetadata(UUID.fromString(uuid));
            if (runMetadata != null) {
                // TODO: Check if workflow was previously implemented using legacy
                //  state tracking. If yes, map the new run metadata to legacy
                //  WorkflowState object(s) to allow smooth transition for clients.

                return Response
                        .status(Response.Status.MOVED_PERMANENTLY)
                        .location(uriInfo.getBaseUriBuilder()
                                .path("/api/v2/workflow-runs/{id}")
                                .build(uuid))
                        .build();
            }

            // For the transitional period, workflows can exist in either the dedicated
            // dex engine, or the legacy workflow state tracking mechanism.
            //
            // The fact that nothing was found in the dex engine is not sufficient
            // to justify a 404.
            //
            // TODO: Change this when legacy state tracking is removed.
        }

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
}
