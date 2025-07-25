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
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.User;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.KeyManager;
import alpine.server.auth.AlpineAuthenticationException;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.auth.Authenticator;
import alpine.server.auth.JsonWebToken;
import alpine.server.auth.OidcAuthenticationService;
import alpine.server.auth.PasswordService;
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
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.IdentifiableObject;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.notification.v1.UserSubject;
import org.dependencytrack.resources.v1.problems.AccessManagementProblemDetails;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.ModifyUserProjectRoleRequest;
import org.dependencytrack.resources.v1.vo.TeamsSetRequest;
import org.owasp.security.logging.SecurityMarkers;

import javax.jdo.Query;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * JAX-RS resources for processing users.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/user")
@Tag(name = "user")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class UserResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(UserResource.class);

    private final KafkaEventDispatcher eventDispatcher = new KafkaEventDispatcher();

    @POST
    @Path("login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(
            summary = "Assert login credentials",
            description = "Upon a successful login, a JSON Web Token will be returned in the response body. This functionality requires authentication to be enabled.")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A bearer token to be used for authenticating with the REST API",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    @AuthenticationNotRequired
    public Response validateCredentials(@FormParam("username") String username, @FormParam("password") String password) {
        final Authenticator auth = new Authenticator(username, password);
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                try {
                    final Principal principal = auth.authenticate();
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_SUCCESS, "Successful user login / username: " + username);
                    final Set<String> permissionNames = qm.getEffectivePermissions(principal);
                    final List<Permission> permissions = qm.getPermissionsByName(permissionNames);
                    final KeyManager km = KeyManager.getInstance();
                    final JsonWebToken jwt = new JsonWebToken(km.getSecretKey());
                    final String token = jwt.createToken(principal, permissions);
                    return Response.ok(token).build();
                } catch (AlpineAuthenticationException e) {
                    if (AlpineAuthenticationException.CauseType.SUSPENDED == e.getCauseType() || AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT == e.getCauseType()) {
                        super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "Unauthorized login attempt / account is suspended / username: " + username);
                        return Response.status(Response.Status.FORBIDDEN).entity(e.getCauseType().name()).build();
                    } else {
                        super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "Unauthorized login attempt / invalid credentials / username: " + username);
                        return Response.status(Response.Status.UNAUTHORIZED).entity(e.getCauseType().name()).build();
                    }
                }
            });
        }
    }

    /**
     * @since 4.0.0
     */
    @POST
    @Path("oidc/login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(
            summary = "Login with OpenID Connect",
            description = "Upon a successful login, a JSON Web Token will be returned in the response body. This functionality requires authentication to be enabled.")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A bearer token to be used for authenticating with the REST API",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "204", description = "No Content"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    @AuthenticationNotRequired
    public Response validateOidcAccessToken(@Parameter(description = "An OAuth2 access token", required = true)
                                            @FormParam("idToken") final String idToken,
                                            @FormParam("accessToken") final String accessToken) {
        final OidcAuthenticationService authService = new OidcAuthenticationService(idToken, accessToken);

        if (!authService.isSpecified()) {
            super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "An OpenID Connect login attempt was made, but OIDC is disabled or not properly configured");
            return Response.status(Response.Status.NO_CONTENT).build();
        }

        try (final QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                try {
                    final Principal principal = authService.authenticate();
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_SUCCESS, "Successful OpenID Connect login / username: " + principal.getName());
                    final Set<String> permissionNames = qm.getEffectivePermissions(principal);
                    final List<Permission> permissions = qm.getPermissionsByName(permissionNames);
                    final KeyManager km = KeyManager.getInstance();
                    final JsonWebToken jwt = new JsonWebToken(km.getSecretKey());
                    final String token = jwt.createToken(principal, permissions);
                    return Response.ok(token).build();
                } catch (AlpineAuthenticationException e) {
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "Unauthorized OpenID Connect login attempt");
                    if (AlpineAuthenticationException.CauseType.SUSPENDED == e.getCauseType() || AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT == e.getCauseType()) {
                        return Response.status(Response.Status.FORBIDDEN).entity(e.getCauseType().name()).build();
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity(e.getCauseType().name()).build();
                    }
                }
            });
        }
    }

    @POST
    @Path("forceChangePassword")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(
            summary = "Asserts login credentials and upon successful authentication, verifies passwords match and changes users password",
            description = "Upon a successful login, a JSON Web Token will be returned in the response body. This functionality requires authentication to be enabled."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    @AuthenticationNotRequired
    public Response forceChangePassword(@FormParam("username") String username, @FormParam("password") String password,
            @FormParam("newPassword") String newPassword, @FormParam("confirmPassword") String confirmPassword) {
        final Authenticator auth = new Authenticator(username, password);
        AtomicReference<Principal> principal = new AtomicReference<>();
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                try {
                    try {
                        principal.set(auth.authenticate());
                    } catch (AlpineAuthenticationException e) {
                        if (AlpineAuthenticationException.CauseType.FORCE_PASSWORD_CHANGE == e.getCauseType()) {
                            principal.set(e.getPrincipal());
                        } else {
                            throw new AlpineAuthenticationException(e.getCauseType());
                        }
                    }
                    if (principal.get() instanceof ManagedUser) {
                        final ManagedUser user = qm.getManagedUser(((ManagedUser) principal.get()).getUsername());
                        if (StringUtils.isNotBlank(newPassword) && StringUtils.isNotBlank(confirmPassword) && newPassword.equals(confirmPassword)) {
                            if (PasswordService.matches(newPassword.toCharArray(), user)) {
                                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "Existing password is the same as new password. Password not changed. / username: " + username);
                                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Existing password is the same as new password. Password not changed.").build();
                            } else {
                                user.setPassword(String.valueOf(PasswordService.createHash(newPassword.toCharArray())));
                                user.setForcePasswordChange(false);
                                qm.updateManagedUser(user);
                                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Password successfully changed / username: " + username);
                                return Response.ok().build();
                            }
                        } else {
                            super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "The passwords do not match. Password not changed. / username: " + username);
                            return Response.status(Response.Status.NOT_ACCEPTABLE).entity("The passwords do not match. Password not changed.").build();
                        }
                    } else {
                        super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "Changing passwords for non-managed users is not forbidden. Password not changed. / username: " + username);
                        return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Changing passwords for non-managed users is not forbidden. Password not changed.").build();
                    }
                } catch (AlpineAuthenticationException e) {
                    if (AlpineAuthenticationException.CauseType.SUSPENDED == e.getCauseType() || AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT == e.getCauseType()) {
                        super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "Unauthorized login attempt / account is suspended / username: " + username);
                        return Response.status(Response.Status.FORBIDDEN).entity(e.getCauseType().name()).build();
                    } else {
                        super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_FAILURE, "Unauthorized login attempt / invalid credentials / username: " + username);
                        return Response.status(Response.Status.UNAUTHORIZED).entity(e.getCauseType().name()).build();
                    }
                }
            });
        }
    }

    @GET
    @Path("managed")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all managed users",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all managed users",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of managed users", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ManagedUser.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response getManagedUsers() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final long totalCount = qm.getCount(ManagedUser.class);
            final List<ManagedUser> users = qm.getManagedUsers();
            return Response.ok(users).header(TOTAL_COUNT_HEADER, totalCount).build();
        }
    }

    @GET
    @Path("ldap")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all LDAP users",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all LDAP users",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of LDAP users", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = LdapUser.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response getLdapUsers() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final long totalCount = qm.getCount(LdapUser.class);
            final List<LdapUser> users = qm.getLdapUsers();
            return Response.ok(users).header(TOTAL_COUNT_HEADER, totalCount).build();
        }
    }

    /**
     * @since 4.0.0
     */
    @GET
    @Path("oidc")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all OIDC users",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all OIDC users",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of OIDC users", schema = @Schema(format = "integer"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response getOidcUsers() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final long totalCount = qm.getCount(OidcUser.class);
            final List<OidcUser> users = qm.getOidcUsers();
            return Response.ok(users).header(TOTAL_COUNT_HEADER, totalCount).build();
        }
    }

    @GET
    @Path("self")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns information about the current logged in user."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Information about the current logged in user",
                    content = @Content(schema = @Schema(implementation = User.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getSelf() {
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHENTICATION)) {
            try (QueryManager qm = new QueryManager()) {
                if (super.isLdapUser()) {
                    final LdapUser user = qm.getLdapUser(getPrincipal().getName());
                    return Response.ok(user).build();
                } else if (super.isManagedUser()) {
                    final ManagedUser user = qm.getManagedUser(getPrincipal().getName());
                    return Response.ok(user).build();
                } else if (super.isOidcUser()) {
                    final OidcUser user = qm.getOidcUser(getPrincipal().getName());
                    return Response.ok(user).build();
                }
                return Response.status(401).build();
            }
        }
        // Authentication is not enabled, but we need to return a positive response without any principal data.
        return Response.ok().build();
    }

    @POST
    @Path("self")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates information about the current logged in user."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = ManagedUser.class))
            ),
            @ApiResponse(responseCode = "400", description = "An invalid payload was submitted or the user is not a managed user."),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response updateSelf(ManagedUser jsonUser) {
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHENTICATION)) {
            try (QueryManager qm = new QueryManager()) {
                if (super.isLdapUser()) {
                    final LdapUser user = qm.getLdapUser(getPrincipal().getName());
                    return Response.status(Response.Status.BAD_REQUEST).entity(user).build();
                } else if (super.isOidcUser()) {
                    final OidcUser user = qm.getOidcUser(getPrincipal().getName());
                    return Response.status(Response.Status.BAD_REQUEST).entity(user).build();
                } else if (super.isManagedUser()) {
                    final ManagedUser user = (ManagedUser) super.getPrincipal();
                    if (StringUtils.isBlank(jsonUser.getFullname())) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("Full name is required.").build();
                    }
                    if (StringUtils.isBlank(jsonUser.getEmail())) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("Email address is required.").build();
                    }
                    user.setFullname(StringUtils.trimToNull(jsonUser.getFullname()));
                    user.setEmail(StringUtils.trimToNull(jsonUser.getEmail()));
                    if (StringUtils.isNotBlank(jsonUser.getNewPassword()) && StringUtils.isNotBlank(jsonUser.getConfirmPassword())) {
                        if (jsonUser.getNewPassword().equals(jsonUser.getConfirmPassword())) {
                            user.setPassword(String.valueOf(PasswordService.createHash(jsonUser.getNewPassword().toCharArray())));
                        } else {
                            return Response.status(Response.Status.BAD_REQUEST).entity("Passwords do not match.").build();
                        }
                    }
                    qm.updateManagedUser(user);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "User profile updated: " + user.getUsername());
                    return Response.ok(user).build();
                }
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
        }
        // Authentication is not enabled, but we need to return a positive response without any principal data.
        return Response.ok().build();
    }

    @PUT
    @Path("ldap")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new user that references an existing LDAP object.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created LDAP user",
                    content = @Content(schema = @Schema(implementation = LdapUser.class))
            ),
            @ApiResponse(responseCode = "400", description = "Username cannot be null or blank."),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A user with the same username already exists. Cannot create new user")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createLdapUser(LdapUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                if (StringUtils.isBlank(jsonUser.getUsername())) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Username cannot be null or blank.").build();
                }
                LdapUser user = qm.getLdapUser(jsonUser.getUsername());
                if (user == null) {
                    user = qm.createLdapUser(jsonUser.getUsername());
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "LDAP user created: " + jsonUser.getUsername());
                    dispatchUserCreatedNotification("LDAP user created", buildUserSubject(jsonUser.getUsername(), jsonUser.getEmail()));
                    return Response.status(Response.Status.CREATED).entity(user).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A user with the same username already exists. Cannot create new user.").build();
                }
            });
        }
    }

    @DELETE
    @Path("ldap")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "LDAP user removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteLdapUser(LdapUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final LdapUser user = qm.getLdapUser(jsonUser.getUsername());
                if (user != null) {
                    final LdapUser detachedUser = qm.getPersistenceManager().detachCopy(user);
                    qm.delete(user);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "LDAP user deleted: " + detachedUser.getUsername());
                    dispatchUserDeletedNotification("LDAP user deleted", buildUserSubject(detachedUser.getUsername(), detachedUser.getEmail()));
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }
            });
        }
    }

    @PUT
    @Path("managed")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created user",
                    content = @Content(schema = @Schema(implementation = ManagedUser.class))
            ),
            @ApiResponse(responseCode = "400", description = "Missing required field"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A user with the same username already exists. Cannot create new user")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createManagedUser(ManagedUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                if (StringUtils.isBlank(jsonUser.getUsername())) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Username cannot be null or blank.").build();
                }
                if (StringUtils.isBlank(jsonUser.getFullname())) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The users full name is missing.").build();
                }
                if (StringUtils.isBlank(jsonUser.getEmail())) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The users email address is missing.").build();
                }
                if (StringUtils.isBlank(jsonUser.getNewPassword()) || StringUtils.isBlank(jsonUser.getConfirmPassword())) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("A password must be set.").build();
                }
                if (!jsonUser.getNewPassword().equals(jsonUser.getConfirmPassword())) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The passwords do not match.").build();
                }

                ManagedUser user = qm.getManagedUser(jsonUser.getUsername());
                if (user == null) {
                    user = qm.createManagedUser(jsonUser.getUsername(), jsonUser.getFullname(), jsonUser.getEmail(),
                            String.valueOf(PasswordService.createHash(jsonUser.getNewPassword().toCharArray())),
                            jsonUser.isForcePasswordChange(), jsonUser.isNonExpiryPassword(), jsonUser.isSuspended());
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Managed user created: " + jsonUser.getUsername());
                    dispatchUserCreatedNotification("Managed user created", buildUserSubject(jsonUser.getUsername(), jsonUser.getEmail()));
                    return Response.status(Response.Status.CREATED).entity(user).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A user with the same username already exists. Cannot create new user.").build();
                }
            });
        }
    }

    @POST
    @Path("managed")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a managed user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = ManagedUser.class))
            ),
            @ApiResponse(responseCode = "400", description = "Missing required field"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response updateManagedUser(ManagedUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                ManagedUser user = qm.getManagedUser(jsonUser.getUsername());
                if (user != null) {
                    if (StringUtils.isBlank(jsonUser.getFullname())) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("The users full name is missing.").build();
                    }
                    if (StringUtils.isBlank(jsonUser.getEmail())) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("The users email address is missing.").build();
                    }
                    if (StringUtils.isNotBlank(jsonUser.getNewPassword()) && StringUtils.isNotBlank(jsonUser.getConfirmPassword()) &&
                            jsonUser.getNewPassword().equals(jsonUser.getConfirmPassword())) {
                        user.setPassword(String.valueOf(PasswordService.createHash(jsonUser.getNewPassword().toCharArray())));
                    }
                    user.setFullname(jsonUser.getFullname());
                    user.setEmail(jsonUser.getEmail());
                    user.setForcePasswordChange(jsonUser.isForcePasswordChange());
                    user.setNonExpiryPassword(jsonUser.isNonExpiryPassword());
                    user.setSuspended(jsonUser.isSuspended());
                    user = qm.updateManagedUser(user);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Managed user updated: " + jsonUser.getUsername());
                    return Response.ok(user).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }
            });
        }
    }

    @DELETE
    @Path("managed")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "User removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteManagedUser(ManagedUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final ManagedUser user = qm.getManagedUser(jsonUser.getUsername());
                if (user != null) {
                    final ManagedUser detachedUser = qm.getPersistenceManager().detachCopy(user);
                    qm.delete(user);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Managed user deleted: " + detachedUser.getUsername());
                    dispatchUserDeletedNotification("Managed user deleted", buildUserSubject(detachedUser.getUsername(), detachedUser.getEmail()));
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }
            });
        }
    }

    @PUT
    @Path("oidc")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new user that references an existing OpenID Connect user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created OIDC user",
                    content = @Content(schema = @Schema(implementation = OidcUser.class))
            ),
            @ApiResponse(responseCode = "400", description = "Username cannot be null or blank."),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A user with the same username already exists. Cannot create new user")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createOidcUser(final OidcUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                if (StringUtils.isBlank(jsonUser.getUsername())) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Username cannot be null or blank.").build();
                }
                OidcUser user = qm.getOidcUser(jsonUser.getUsername());
                if (user == null) {
                    user = qm.createOidcUser(jsonUser.getUsername());
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "OpenID Connect user created: " + jsonUser.getUsername());
                    dispatchUserCreatedNotification("OpenID Connect user created", buildUserSubject(jsonUser.getUsername(), jsonUser.getEmail()));
                    return Response.status(Response.Status.CREATED).entity(user).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A user with the same username already exists. Cannot create new user.").build();
                }
            });
        }
    }

    @DELETE
    @Path("oidc")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes an OpenID Connect user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "OIDC user removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteOidcUser(final OidcUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final OidcUser user = qm.getOidcUser(jsonUser.getUsername());
                if (user != null) {
                    final OidcUser detachedUser = qm.getPersistenceManager().detachCopy(user);
                    qm.delete(user);
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "OpenID Connect user deleted: " + detachedUser.getUsername());
                    dispatchUserDeletedNotification("OpenID Connect user deleted", buildUserSubject(detachedUser.getUsername(), detachedUser.getEmail()));
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }
            });
        }
    }

    @POST
    @Path("/{username}/membership")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds the username to the specified team.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = User.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user is already a member of the specified team"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user or team could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response addTeamToUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "The UUID of the team to associate username with", required = true)
            IdentifiableObject identifiableObject) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final Team team = qm.getObjectByUuid(Team.class, identifiableObject.getUuid());
                if (team == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
                }
                User principal = qm.getUser(username);
                if (principal == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }
                final boolean modified = qm.addUserToTeam(principal, team);
                qm.getPersistenceManager().refresh(principal);
                principal = qm.getObjectById(principal.getClass(), principal.getId());
                if (modified) {
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Added team membership for: " + principal.getName() + " / team: " + team.getName());
                    return Response.ok(principal).build();
                } else {
                    return Response.status(Response.Status.NOT_MODIFIED).entity("The user is already a member of the specified team.").build();
                }
            });
        }
    }

    @DELETE
    @Path("/{username}/membership")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes the username from the specified team.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = User.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user was not a member of the specified team"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user or team could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response removeTeamFromUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "The UUID of the team to un-associate username from", required = true)
            IdentifiableObject identifiableObject) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final Team team = qm.getObjectByUuid(Team.class, identifiableObject.getUuid());
                if (team == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
                }
                User principal = qm.getUser(username);
                if (principal == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }
                final boolean modified = qm.removeUserFromTeam(principal, team);
                principal = qm.getObjectById(principal.getClass(), principal.getId());
                if (modified) {
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Removed team membership for: " + principal.getName() + " / team: " + team.getName());
                    return Response.ok(principal).build();
                } else {
                    return Response.status(Response.Status.NOT_MODIFIED)
                            .entity("The user was not a member of the specified team.")
                            .build();
                }
            });
        }
    }

    @PUT
    @Path("/membership")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Sets specified teams to a user.", description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated user", content = @Content(schema = @Schema(implementation = User.class))),
            @ApiResponse(responseCode = "304", description = "The user is already a member of the specified team(s)"),
            @ApiResponse(responseCode = "400", description = "Bad request", content = @Content(schema = @Schema(implementation = AccessManagementProblemDetails.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user or team(s) could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response setUserTeams(
            @Parameter(description = "Username and list of UUIDs to assign to user", required = true) @Valid TeamsSetRequest request) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                User principal = qm.getUser(request.username());
                if (principal == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
                }

                final Query<Team> query = qm.getPersistenceManager().newQuery(Team.class)
                        .filter(":uuids.contains(uuid)")
                        .setNamedParameters(Map.of("uuids", request.teams()));

                final List<Team> requestedTeams;
                try {
                    requestedTeams = List.copyOf(query.executeList());
                } finally {
                    query.closeAll();
                }

                if (requestedTeams.size() != request.teams().size()) {
                    List<String> notFound = new ArrayList<String>(request.teams());
                    final List<String> differences = requestedTeams.stream().map(Team::getUuid).map(UUID::toString).toList();
                    notFound.removeAll(differences);

                    ProblemDetails problem = new AccessManagementProblemDetails(
                            Response.Status.BAD_REQUEST.getStatusCode(),
                            "Invalid team",
                            "One or more teams could not be found",
                            notFound);

                    return problem.toResponse();
                }

                final List<Team> currentUserTeams = Objects.requireNonNullElse(principal.getTeams(), List.<Team>of());
                if (currentUserTeams.equals(requestedTeams)) {
                    return Response.notModified().entity("The user is already a member of the selected team(s)").build();
                }

                principal.setTeams(requestedTeams);
                qm.persist(principal);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Added team membership for: " + principal.getName() + " / team: " + requestedTeams.toString());
                return Response.ok(principal).build();
            });
        }
    }

    private void dispatchUserCreatedNotification(final String content, final UserSubject subject) {
        eventDispatcher.dispatchNotification(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.USER_CREATED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.USER_CREATED)
                .content(content)
                .subject(subject));
    }

    private void dispatchUserDeletedNotification(final String content, final UserSubject subject) {
        eventDispatcher.dispatchNotification(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.USER_DELETED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.USER_DELETED)
                .content(content)
                .subject(subject));
    }

    private UserSubject buildUserSubject(final String username, final String email) {
        var userBuilder = UserSubject.newBuilder().setUsername(username);
        Optional.ofNullable(email).ifPresent(userBuilder::setEmail);
        return userBuilder.build();
    }

    @SuppressWarnings("null")
    @PUT
    @Path("/role")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Assigns or updates a user's role for a project.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User with the specified role assigned or updated", content = @Content(schema = @Schema(implementation = User.class))),
            @ApiResponse(responseCode = "304", description = "The user already has this role for the project."),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user, role, or project could not be found", content = @Content(schema = @Schema(implementation = AccessManagementProblemDetails.class)))
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response assignProjectRoleToUser(
            @Parameter(description = "User, Role and Project information", required = true) @Valid ModifyUserProjectRoleRequest request) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final Role role = qm.getObjectByUuid(Role.class, request.role());
                final User user = qm.getUser(request.username());
                final Project project = qm.getProject(request.project());

                List<String> problems = new ArrayList<>();
                if (role == null) problems.add("role");
                if (user == null) problems.add("user");
                if (project == null) problems.add("project");

                if (!problems.isEmpty())
                    return new AccessManagementProblemDetails(
                            Response.Status.NOT_FOUND.getStatusCode(),
                            "Invalid role, user or project",
                            "One or more variables could not be found",
                            problems).toResponse();

                if (!qm.addRoleToUser(user, role, project))
                    return Response.notModified().build();

                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Granted project role: user='%s', role='%s', project='%s'"
                                .formatted(user.getUsername(), role.getName(), project.getName()));

                return Response.ok(user).build();
            });
        }
    }

    @SuppressWarnings("null")
    @DELETE
    @Path("/role")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes a specific role for a user from a project.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "The specified role was successfully removed from the user"),
            @ApiResponse(responseCode = "304", description = "The user is not a member of the specified role for the project"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404",description = "The user, role, or project could not be found",content = @Content(schema = @Schema(implementation = AccessManagementProblemDetails.class)))
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response removeProjectRoleFromUser(
            @Parameter(description = "User, Role and Project information", required = true) @Valid ModifyUserProjectRoleRequest request) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final Role role = qm.getObjectByUuid(Role.class, request.role());
                final User user = qm.getUser(request.username());
                final Project project = qm.getProject(request.project());

                final List<String> problems = new ArrayList<>();
                if (role == null) problems.add("role");
                if (user == null) problems.add("user");
                if (project == null) problems.add("project");

                if (!problems.isEmpty())
                    return new AccessManagementProblemDetails(
                            Response.Status.NOT_FOUND.getStatusCode(),
                            "Invalid role, user or project",
                            "One or more variables could not be found",
                            problems).toResponse();

                boolean removed = qm.removeRoleFromUser(user, role, project);
                if (!removed) return Response.notModified().build();

                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Revoked project role: user='%s', role='%s', project='%s'"
                                .formatted(user.getUsername(), role.getName(), project.getName()));

                return Response.noContent().build();
            });
        }
    }
}
