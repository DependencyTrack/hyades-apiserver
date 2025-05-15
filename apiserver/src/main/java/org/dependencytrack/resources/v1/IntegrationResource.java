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

import alpine.event.framework.Event;
import alpine.model.ConfigProperty;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.GitLabIntegrationStateEvent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.OsvMirrorTask;

import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;

import java.util.List;
import java.util.stream.Collectors;

@Path("/v1/integration")
@Tag(name = "integration")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class IntegrationResource extends AlpineResource {

    @GET
    @Path("/osv/ecosystem")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all ecosystems in OSV",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all ecosystems in OSV",
                    content = @Content(array = @ArraySchema(schema = @Schema(type = "string")))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_READ})
    public Response getAllEcosystems() {
        OsvMirrorTask osvMirrorTask = new OsvMirrorTask();
        final List<String> ecosystems = osvMirrorTask.getEcosystems();
        return Response.ok(ecosystems).build();
    }

    @GET
    @Path("/osv/ecosystem/inactive")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of available inactive ecosystems in OSV to be selected by user",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of available inactive ecosystems in OSV to be selected by user",
                    content = @Content(array = @ArraySchema(schema = @Schema(type = "string")))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_READ})
    public Response getInactiveEcosystems() {
        OsvMirrorTask osvMirrorTask = new OsvMirrorTask();
        var selectedEcosystems = osvMirrorTask.getEnabledEcosystems();
        final List<String> ecosystems = osvMirrorTask.getEcosystems().stream()
                .filter(element -> !selectedEcosystems.contains(element))
                .collect(Collectors.toList());
        return Response.ok(ecosystems).build();
    }

    @POST
    @Path("gitlab/{state}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Set state of gitlab integration", description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Gitlab state set successfully"),
            @ApiResponse(responseCode = "304", description = "The GitLab integration is already in the desired state"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({ Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE }) // Require admin privileges due to system impact
    public Response handleGitlabStateChange(
            @Parameter(description = "A valid boolean", required = true) @PathParam("state") String state) {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(GITLAB_ENABLED.getGroupName(),
                    GITLAB_ENABLED.getPropertyName());

            if (!property.getPropertyValue().equals(state)) {
                if (!state.equalsIgnoreCase("true") && !state.equalsIgnoreCase("false")) {
                    return Response.status(Response.Status.BAD_REQUEST).build();
                }
                property.setPropertyValue(state);
                qm.persist(property);
                Event.dispatch(new GitLabIntegrationStateEvent());
            }
        }

        return Response.ok().build();
    }
}
