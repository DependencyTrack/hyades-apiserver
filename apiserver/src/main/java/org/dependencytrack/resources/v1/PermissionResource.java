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
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.User;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Role;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.RolePermissionsSetRequest;
import org.dependencytrack.resources.v1.vo.TeamPermissionsSetRequest;
import org.dependencytrack.resources.v1.vo.UserPermissionsSetRequest;
import org.owasp.security.logging.SecurityMarkers;

import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Set;

/**
 * JAX-RS resources for processing permissions.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/permission")
@Tag(name = "permission")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class PermissionResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(PermissionResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all permissions",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all permissions",
                    content = @Content(schema = @Schema(implementation = Permissions.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response getAllPermissions() {
        try (QueryManager qm = new QueryManager()) {
            final List<Permission> permissions = qm.getPermissions();
            return Response.ok(permissions).build();
        }
    }

    @POST
    @Path("/{permission}/user/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds the permission to the specified username.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = User.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response addPermissionToUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                User user = qm.getUser(username);
                if (user == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }
                final Permission permission = qm.getPermission(permissionName);
                if (permission == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
                }
                final List<Permission> permissions = user.getPermissions();
                if (permissions != null && !permissions.contains(permission)) {
                    permissions.add(permission);
                    user.setPermissions(permissions);
                    user = qm.persist(user);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Added permission for user: " + user.getName() + " / permission: " + permission.getName());
                    return Response.ok(user).build();
                }
                return Response.status(Response.Status.NOT_MODIFIED).build();
            });
        }
    }

    @DELETE
    @Path("/{permission}/user/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes the permission from the user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = User.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response removePermissionFromUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "A valid permission", required = true)
            @QueryParam("userType") String type,
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                User user = qm.getUser(username, (Class<? extends User>) switch (StringUtils.defaultString(type).toLowerCase()) {
                    case "managed" -> ManagedUser.class;
                    case "ldap" -> LdapUser.class;
                    case "oidc" -> OidcUser.class;
                    default -> User.class;
                });

                if (user == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }

                final Permission permission = qm.getPermission(permissionName);
                if (permission == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
                }

                final List<Permission> permissions = user.getPermissions();
                if (permissions != null && permissions.contains(permission)) {
                    permissions.remove(permission);
                    user.setPermissions(permissions);
                    user = qm.persist(user);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                            "Removed permission for user: " + user.getUsername() + " / permission: "
                                    + permission.getName());
                    return Response.ok(user).build();
                }

                return Response.status(Response.Status.NOT_MODIFIED).build();
            });
        }
    }

    @POST
    @Path("/{permission}/team/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated team",
                    content = @Content(schema = @Schema(implementation = Team.class))
            ),
            @ApiResponse(responseCode = "304", description = "The team already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response addPermissionToTeam(
            @Parameter(description = "A valid team uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                Team team = qm.getObjectByUuid(Team.class, uuid);
                if (team == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
                }

                final Permission permission = qm.getPermission(permissionName);
                if (permission == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
                }

                final List<Permission> permissions = team.getPermissions();
                if (permissions != null && !permissions.contains(permission)) {
                    permissions.add(permission);
                    team.setPermissions(permissions);
                    team = qm.persist(team);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Added permission for team: " + team.getName() + " / permission: " + permission.getName());
                    return Response.ok(team).build();
                }

                return Response.status(Response.Status.NOT_MODIFIED).build();
            });
        }
    }

    @DELETE
    @Path("/{permission}/role/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated role", content = @Content(schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "304", description = "The role already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The role could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE })
    public Response removePermissionFromRole(
            @Parameter(description = "A valid role uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                Role role = qm.getObjectByUuid(Role.class, uuid);
                if (role == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The role could not be found.").build();

                final Permission permission = qm.getPermission(permissionName);
                if (permission == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();

                final Set<Permission> permissions = role.getPermissions();
                if (permissions != null && permissions.contains(permission)) {
                    permissions.remove(permission);
                    role.setPermissions(permissions);
                    role = qm.persist(role);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Removed permission for role: " + role.getName() + " / permission: " + permission.getName());
                    return Response.ok(role).build();
                }

                return Response.notModified().build();
            });
        }
    }

    @POST
    @Path("/{permission}/role/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated role", content = @Content(schema = @Schema(implementation = Role.class))
            ),
            @ApiResponse(responseCode = "304", description = "The role already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The role could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response addPermissionToRole(
            @Parameter(description = "A valid role uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                Role role = qm.getObjectByUuid(Role.class, uuid);
                if (role == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The role could not be found.").build();

                final Permission permission = qm.getPermission(permissionName);
                if (permission == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();

                if (!qm.addPermissionToRole(role, permission))
                    return Response.notModified().build();

                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Added permission for role: " + role.getName() + " / permission: " + permission.getName());

                return Response.ok(role).build();
            });
        }
    }

    @DELETE
    @Path("/{permission}/team/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated team",
                    content = @Content(schema = @Schema(implementation = Team.class))
            ),
            @ApiResponse(responseCode = "304", description = "The team already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response removePermissionFromTeam(
            @Parameter(description = "A valid team uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                Team team = qm.getObjectByUuid(Team.class, uuid, Team.FetchGroup.ALL.name());
                if (team == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
                }
                final Permission permission = qm.getPermission(permissionName);
                if (permission == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
                }
                final List<Permission> permissions = team.getPermissions();
                if (permissions != null && permissions.contains(permission)) {
                    permissions.remove(permission);
                    team.setPermissions(permissions);
                    team = qm.persist(team);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Removed permission for team: " + team.getName() + " / permission: " + permission.getName());
                    return Response.ok(team).build();
                }
                return Response.status(Response.Status.NOT_MODIFIED).build();
            });
        }
    }

    @PUT
    @Path("/user")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Replaces a users's permissions with the specified list",
        description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated user", content = @Content(schema = @Schema(implementation = User.class))),
            @ApiResponse(responseCode = "304", description = "The user is already has the specified permission(s)"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response setUserPermissions(
            @Parameter(description = "A username and valid list permission") @Valid final UserPermissionsSetRequest request) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                User user = qm.getUser(request.username(), (Class<? extends User>) switch (StringUtils.defaultString(request.userType()).toLowerCase()) {
                    case "managed" -> ManagedUser.class;
                    case "ldap" -> LdapUser.class;
                    case "oidc" -> OidcUser.class;
                    default -> User.class;
                });

                if (user == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();

                final List<String> permissionNames = request.permissions()
                        .stream()
                        .map(Permissions::name)
                        .toList();

                final List<Permission> requestedPermissions = qm.getPermissionsByName(permissionNames);

                if (user.getPermissions().equals(requestedPermissions))
                    return Response.notModified()
                            .entity("User already has selected permission(s).")
                            .build();

                user.setPermissions(requestedPermissions);
                user = qm.persist(user);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Set permissions for user: %s / permissions: %s"
                                .formatted(user.getUsername(), permissionNames));

                return Response.ok(user).build();
            });
        }
    }

    @PUT
    @Path("/team")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Replaces a team's permissions with the specified list",
        description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated team", content = @Content(schema = @Schema(implementation = Team.class))),
            @ApiResponse(responseCode = "304", description = "The team already has the specified permission(s)"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response setTeamPermissions(@Parameter(description = "Team UUID and requested permissions") @Valid final TeamPermissionsSetRequest request) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                Team team = qm.getObjectByUuid(Team.class, request.team(), Team.FetchGroup.ALL.name());
                if (team == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();

                final List<String> permissionNames = request.permissions()
                        .stream()
                        .map(Permissions::name)
                        .toList();

                final List<Permission> requestedPermissions = qm.getPermissionsByName(permissionNames);

                if (team.getPermissions().equals(requestedPermissions))
                    return Response.notModified().entity("Team already has selected permission(s).").build();

                team.setPermissions(requestedPermissions);
                team = qm.persist(team);

                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Set permissions for team: %s / permissions: %s"
                                .formatted(team.getName(), permissionNames));
                return Response.ok(team).build();
            });
        }
    }

    @PUT
    @Path("/role")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Replaces a role's permissions with the specified list",
        description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated role", content = @Content(schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "304", description = "The role already has the specified permission(s)"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The role could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response setRolePermissions(@Parameter(description = "Role UUID and requested permissions") @Valid final RolePermissionsSetRequest request) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                Role role = qm.getObjectByUuid(Role.class, request.role(), Role.FetchGroup.ALL.name());
                if (role == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The role could not be found.").build();

                final List<String> permissionNames = request.permissions()
                        .stream()
                        .map(Permissions::name)
                        .toList();

                final Set<Permission> requestedPermissions = Set.copyOf(qm.getPermissionsByName(permissionNames));

                if (role.getPermissions().equals(requestedPermissions))
                    return Response.notModified().entity("Role already has selected permission(s).").build();

                role.setPermissions(requestedPermissions);
                role = qm.persist(role);

                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Set permissions for role: %s / permissions: %s"
                                .formatted(role.getName(), permissionNames));

                return Response.ok(role).build();
            });
        }
    }

}
