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
import alpine.server.resources.AlpineResource;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.model.Role;
import org.dependencytrack.model.ProjectRole;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.RoleDao;
import org.jdbi.v3.core.Handle;
import org.owasp.security.logging.SecurityMarkers;

import alpine.model.UserPrincipal;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

import java.util.List;

/**
 * JAX-RS resources for processing roles.
 *
 * @author Johnny Mayer
 * @since 5.6.0
 */
@Path("/v1/role")
@Tag(name = "role")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class RoleResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(RoleResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all roles",
            description = "<p>Requires permission <strong>ROLE_MANAGEMENT</strong> or <strong>ROLE_MANAGEMENT_READ</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all roles",
                    headers = @Header(
                            name = TOTAL_COUNT_HEADER,
                            description = "The total number of roles",
                            schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Role.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({ Permissions.Constants.ROLE_MANAGEMENT, Permissions.Constants.ROLE_MANAGEMENT_READ })
    public Response getRoles() {
        try (QueryManager qm = new QueryManager()) {
            return Response.ok(qm.getRoles()).header(TOTAL_COUNT_HEADER, qm.getCount(Role.class)).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific role",
            description = "<p>Requires permission <strong>ROLE_MANAGEMENT</strong> or <strong>ROLE_MANAGEMENT_READ</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific role",
                    content = @Content(schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The role could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ROLE_MANAGEMENT, Permissions.Constants.ROLE_MANAGEMENT_READ })
    public Response getRole(
            @Parameter(
                    description = "The UUID of the role to retrieve",
                    schema = @Schema(type = "string", format = "uuid"),
                    required = true) @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            Role role = qm.getObjectByUuid(Role.class, uuid);
            if (role == null)
                return Response.status(Response.Status.NOT_FOUND).entity("The role could not be found.").build();

            return Response.ok(role).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new role",
            description = "<p>Requires permission <strong>ROLE_MANAGEMENT</strong> or <strong>ROLE_MANAGEMENT_CREATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created role",
                    content = @Content(schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({ Permissions.Constants.ROLE_MANAGEMENT, Permissions.Constants.ROLE_MANAGEMENT_CREATE })
    public Response createRole(Role jsonRole) {
        failOnValidationError(super.getValidator().validateProperty(jsonRole, "name"));

        try (QueryManager qm = new QueryManager()) {
            final Role role = qm.createRole(jsonRole.getName(), jsonRole.getPermissions().stream().toList());
            super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Role created: " + role.getName());

            return Response.status(Response.Status.CREATED).entity(role).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a role's fields",
            description = "<p>Requires permission <strong>ROLE_MANAGEMENT</strong> or <strong>ROLE_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated role",
                    content = @Content(schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The role could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ROLE_MANAGEMENT, Permissions.Constants.ROLE_MANAGEMENT_UPDATE })
    public Response updateRole(Role jsonRole) {
        failOnValidationError(super.getValidator().validateProperty(jsonRole, "name"));

        try (QueryManager qm = new QueryManager()) {
            Role role = qm.updateRole(jsonRole);
            if (role == null)
                return Response.status(Response.Status.NOT_FOUND).entity("The role could not be found.").build();

            super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Role updated: " + role.getName());

            return Response.ok(role).build();
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a role",
            description = "<p>Requires permission <strong>ROLE_MANAGEMENT</strong> or <strong>ROLE_MANAGEMENT_DELETE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Role removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The role could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ROLE_MANAGEMENT, Permissions.Constants.ROLE_MANAGEMENT_DELETE })
    public Response deleteRole(Role jsonRole) {
        try (QueryManager qm = new QueryManager()) {
            final Role role = qm.getObjectByUuid(Role.class, jsonRole.getUuid(), Role.FetchGroup.ALL.name());
            if (role == null)
                return Response.status(Response.Status.NOT_FOUND).entity("The role could not be found.").build();

            try (final Handle jdbiHandle = openJdbiHandle()) {
                jdbiHandle.attach(RoleDao.class).deleteRole(role.getId());
            }

            super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Role deleted: " + role.getName());

            return Response.noContent().build();
        }
    }

    @GET
    @Path("/{username}/roles")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of roles assigned to the specified user",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_READ</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of roles assigned to the user",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ProjectRole.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ })
    public Response getUserRoles(
            @Parameter(description = "A valid username", required = true) @PathParam("username") String username) {
        try (QueryManager qm = new QueryManager()) {
            UserPrincipal principal = qm.getUserPrincipal(username);
            if (principal == null) {
                LOGGER.warn("User not found: " + username);
                return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
            }

            List<? extends ProjectRole> roles = qm.getUserRoles(principal);
            if (roles == null || roles.isEmpty()) {
                LOGGER.info("No roles found for user: " + username);
                return Response.ok(List.of()).build();
            }
            
            return Response.ok(roles).build();
        }
    }
}
