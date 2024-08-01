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
import jakarta.validation.Validator;
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
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.notification.publisher.PublisherClass;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * JAX-RS resources for processing notification publishers.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/notification/publisher")
@Tag(name = "notification")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class NotificationPublisherResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(NotificationPublisherResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of all notification publishers",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content(array = @ArraySchema(schema = @Schema(implementation = NotificationPublisher.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_READ})
    public Response getAllNotificationPublishers() {
        try (QueryManager qm = new QueryManager()) {
            final List<NotificationPublisher> publishers = qm.getAllNotificationPublishers();
            return Response.ok(publishers).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new notification publisher",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", content = @Content(schema = @Schema(implementation = NotificationPublisher.class))),
            @ApiResponse(responseCode = "400", description = "Invalid notification class or trying to modify a default publisher"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "Conflict with an existing publisher's name")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_CREATE})
    public Response createNotificationPublisher(NotificationPublisher jsonNotificationPublisher) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonNotificationPublisher, "name"),
                validator.validateProperty(jsonNotificationPublisher, "publisherClass"),
                validator.validateProperty(jsonNotificationPublisher, "description"),
                validator.validateProperty(jsonNotificationPublisher, "templateMimeType"),
                validator.validateProperty(jsonNotificationPublisher, "template")
        );

        try (QueryManager qm = new QueryManager()) {
            NotificationPublisher existingNotificationPublisher = qm.getNotificationPublisher(jsonNotificationPublisher.getName());
            if (existingNotificationPublisher != null) {
                return Response.status(Response.Status.CONFLICT).entity("The notification with the name " + jsonNotificationPublisher.getName() + " already exist").build();
            }

            if (jsonNotificationPublisher.isDefaultPublisher()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("The creation of a new default publisher is forbidden").build();
            }
            if (Arrays.stream(PublisherClass.values()).anyMatch(clazz ->
                    clazz.name().equalsIgnoreCase(jsonNotificationPublisher.getPublisherClass()))) {
                NotificationPublisher notificationPublisherCreated = qm.createNotificationPublisher(
                        jsonNotificationPublisher.getName(), jsonNotificationPublisher.getDescription(),
                        jsonNotificationPublisher.getPublisherClass(), jsonNotificationPublisher.getTemplate(), jsonNotificationPublisher.getTemplateMimeType(),
                        jsonNotificationPublisher.isDefaultPublisher()
                );
                return Response.status(Response.Status.CREATED).entity(notificationPublisherCreated).build();
            } else {
                return Response.status(Response.Status.BAD_REQUEST).entity("The publisher class " + jsonNotificationPublisher.getPublisherClass() + " is not valid.").build();
            }
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a notification publisher",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content(schema = @Schema(implementation = NotificationPublisher.class))),
            @ApiResponse(responseCode = "400", description = "Invalid notification class or trying to modify a default publisher"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The notification publisher could not be found"),
            @ApiResponse(responseCode = "409", description = "Conflict with an existing publisher's name")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE})
    public Response updateNotificationPublisher(NotificationPublisher jsonNotificationPublisher) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonNotificationPublisher, "name"),
                validator.validateProperty(jsonNotificationPublisher, "publisherClass"),
                validator.validateProperty(jsonNotificationPublisher, "description"),
                validator.validateProperty(jsonNotificationPublisher, "templateMimeType"),
                validator.validateProperty(jsonNotificationPublisher, "template"),
                validator.validateProperty(jsonNotificationPublisher, "uuid")
        );

        try (QueryManager qm = new QueryManager()) {
            NotificationPublisher existingPublisher = qm.getObjectByUuid(NotificationPublisher.class, jsonNotificationPublisher.getUuid());
            if (existingPublisher != null) {
                if (existingPublisher.isDefaultPublisher()) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The modification of a default publisher is forbidden").build();
                }

                if (!jsonNotificationPublisher.getName().equals(existingPublisher.getName())) {
                    NotificationPublisher existingNotificationPublisherWithModifiedName = qm.getNotificationPublisher(jsonNotificationPublisher.getName());
                    if (existingNotificationPublisherWithModifiedName != null) {
                        return Response.status(Response.Status.CONFLICT).entity("An existing publisher with the name '" + existingNotificationPublisherWithModifiedName.getName() + "' already exist").build();
                    }
                }
                existingPublisher.setName(jsonNotificationPublisher.getName());
                existingPublisher.setDescription(jsonNotificationPublisher.getDescription());

                if (Arrays.stream(PublisherClass.values()).anyMatch(clazz ->
                        clazz.name().equalsIgnoreCase(jsonNotificationPublisher.getPublisherClass()))) {
                    existingPublisher.setPublisherClass(jsonNotificationPublisher.getPublisherClass());
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The publisher class " + jsonNotificationPublisher.getPublisherClass() + " is not valid.").build();
                }
                existingPublisher.setTemplate(jsonNotificationPublisher.getTemplate());
                existingPublisher.setTemplateMimeType(jsonNotificationPublisher.getTemplateMimeType());
                existingPublisher.setDefaultPublisher(false);
                NotificationPublisher notificationPublisherUpdated = qm.updateNotificationPublisher(existingPublisher);
                return Response.ok(notificationPublisherUpdated).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification publisher could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{notificationPublisherUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a notification publisher and all related notification rules",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204"),
            @ApiResponse(responseCode = "400", description = "Deleting a default notification publisher is forbidden"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired({ Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE })
    public Response deleteNotificationPublisher(@Parameter(description = "The UUID of the notification publisher to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
                                                @PathParam("notificationPublisherUuid") @ValidUuid String notificationPublisherUuid) {
        try (QueryManager qm = new QueryManager()) {
            final NotificationPublisher notificationPublisher = qm.getObjectByUuid(NotificationPublisher.class, notificationPublisherUuid);
            if (notificationPublisher != null) {
                if (notificationPublisher.isDefaultPublisher()) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Deleting a default notification publisher is forbidden.").build();
                } else {
                    qm.deleteNotificationPublisher(notificationPublisher);
                    return Response.status(Response.Status.NO_CONTENT).build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification rule could not be found.").build();
            }
        }
    }

    @POST
    @Path("/restoreDefaultTemplates")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Restore the default notification publisher templates using the ones in the solution classpath",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_CREATE})
    public Response restoreDefaultTemplates() {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getGroupName(),
                    ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getPropertyName()
            );
            property.setPropertyValue("false");
            qm.persist(property);
            NotificationUtil.loadDefaultNotificationPublishers(qm);
            return Response.ok().build();
        } catch (IOException ioException) {
            LOGGER.error(ioException.getMessage(), ioException);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Exception occured while restoring default notification publisher templates.").build();
        }
    }
}