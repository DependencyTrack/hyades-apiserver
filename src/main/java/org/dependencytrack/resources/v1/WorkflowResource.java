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
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;

@Path("/v1/workflow")
@Api(value = "workflow", authorizations = @Authorization(value = "X-Api-Key"))
public class WorkflowResource {

    private static final Logger LOGGER = Logger.getLogger(WorkflowResource.class);

    @GET
    @Path("/token/{uuid}/status")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Retrieves workflow states associated with the token received from bom upload .",
            response = WorkflowState.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "Workflow does not exist")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response getWorkflowStates(
            @ApiParam(value = "The UUID of the token to query", required = true)
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
}
