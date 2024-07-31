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

import alpine.persistence.PaginatedResult;
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
import jakarta.validation.constraints.Size;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

import java.util.NoSuchElementException;
import java.util.Set;

@Path("/v1/tag")
@io.swagger.v3.oas.annotations.tags.Tag(name = "tag")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class TagResource extends AlpineResource {

    @GET
    @Path("/{policyUuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all tags associated with a given policy",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of tags", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Tag.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getTags(@Parameter(description = "The UUID of the policy", schema = @Schema(type = "string", format = "uuid"), required = true)
                            @PathParam("policyUuid") @ValidUuid String policyUuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getTags(policyUuid);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @POST
    @Path("/{name}/policy")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Tags one or more policies.",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "204",
                    description = "Policies tagged successfully."
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "A tag with the provided name does not exist.",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)
            )
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response tagPolicies(
            @Parameter(description = "Name of the tag to assign", required = true)
            @PathParam("name") final String tagName,
            @Parameter(
                    description = "UUIDs of policies to tag",
                    required = true,
                    array = @ArraySchema(schema = @Schema(type = "string", format = "uuid"))
            )
            @Size(min = 1, max = 100) final Set<@ValidUuid String> policyUuids
    ) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            qm.tagPolicies(tagName, policyUuids);
        } catch (RuntimeException e) {
            // TODO: Move this to an ExceptionMapper once https://github.com/stevespringett/Alpine/pull/588 is available.
            if (e.getCause() instanceof final NoSuchElementException nseException) {
                return Response
                        .status(404)
                        .header("Content-Type", ProblemDetails.MEDIA_TYPE_JSON)
                        .entity(new ProblemDetails(404, "Resource does not exist", nseException.getMessage()))
                        .build();
            }
            throw e;
        }
        return Response.noContent().build();
    }

    @DELETE
    @Path("/{name}/policy")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Untags one or more policies.",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "204",
                    description = "Policies untagged successfully."
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "A tag with the provided name does not exist.",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)
            )
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response untagPolicies(
            @Parameter(description = "Name of the tag", required = true)
            @PathParam("name") final String tagName,
            @Parameter(
                    description = "UUIDs of policies to untag",
                    required = true,
                    array = @ArraySchema(schema = @Schema(type = "string", format = "uuid"))
            )
            @Size(min = 1, max = 100) final Set<@ValidUuid String> policyUuids
    ) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            qm.untagPolicies(tagName, policyUuids);
        } catch (RuntimeException e) {
            // TODO: Move this to an ExceptionMapper once https://github.com/stevespringett/Alpine/pull/588 is available.
            if (e.getCause() instanceof final NoSuchElementException nseException) {
                return Response
                        .status(404)
                        .header("Content-Type", ProblemDetails.MEDIA_TYPE_JSON)
                        .entity(new ProblemDetails(404, "Resource does not exist", nseException.getMessage()))
                        .build();
            }
            throw e;
        }
        return Response.noContent().build();
    }
}
