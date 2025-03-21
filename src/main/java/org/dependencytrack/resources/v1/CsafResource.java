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
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import jakarta.validation.Validator;
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
import org.apache.commons.codec.binary.Hex;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.CsafMirrorEvent;
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.model.CsafSourceEntity;
import org.dependencytrack.model.Repository;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.tasks.CsafMirrorTask;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

/**
 * Resource for vulnerability policies.
 */
@Path("/v1/csaf")
@Tag(name = "csaf")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CsafResource extends AlpineResource {
    private static final Logger LOGGER = Logger.getLogger(CsafResource.class);

    @POST
    @Path("/trigger-mirror/")
    @Operation(summary = "Triggers the CSAF mirror task manually", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The CSAF mirror task has been triggered"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response triggerMirror() {
        var mirror = new CsafMirrorTask();
        mirror.inform(new CsafMirrorEvent());

        return null;
    }

    @GET
    @Path("/aggregators/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF aggregators", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF entities", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF entities", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafSourceEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response getCsafAggregators(@QueryParam("searchText") String searchText, @QueryParam("pageSize") int pageSize, @QueryParam("pageNumber") int pageNumber) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getCsafSources(true, false);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Path("/aggregators/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new CSAF aggregator", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF aggregator", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "An aggregator with the specified identifier already exists")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response createCsafAggregator(CsafSourceEntity jsonEntity) {
        try (QueryManager qm = new QueryManager()) {
            final CsafSourceEntity csafEntity = qm.createCsafSource(jsonEntity.getName(), jsonEntity.getUrl(),
                    jsonEntity.isEnabled(), true);
            return Response.status(Response.Status.CREATED).entity(csafEntity).build();
        } catch (Exception e) {
            return Response.status(Response.Status.CONFLICT).build();
        }
    }

    @POST
    @Path("/aggregators/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF aggregator", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF aggregator", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The csafEntryId of the aggregator could not be found")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT) // TODO create update only permission
    public Response updateCsafAggregator(CsafSourceEntity jsonEntity) {
        final Validator validator = super.getValidator();
        /*
         * final Validator validator = super.getValidator(); // TODO validate
         * failOnValidationError(validator.validateProperty(jsonRepository,
         * "identifier"),
         * validator.validateProperty(jsonRepository, "url")
         * );
         * //TODO: When the UI changes are updated then this should be a validation
         * check as part of line 201
         * if (jsonRepository.isAuthenticationRequired() == null) {
         * jsonRepository.setAuthenticationRequired(false);
         * }
         */
        try (QueryManager qm = new QueryManager()) {
            // TODO Quickfix: the client will not send the aggregator flag, therefore apply it manually
            jsonEntity.setAggregator(true);
            var csafEntity = qm.updateCsafSource(jsonEntity);
            if(csafEntity == null) {
                return Response.status(Response.Status.NOT_FOUND)
                                .entity("The ID of the aggregator could not be found.").build();
            }
            return Response.ok(csafEntity).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                            .entity("The specified CSAF aggregator could not be updated").build();
        }
    }

    @DELETE
    @Path("/aggregators/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a CSAF aggregator", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF source removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF source could not be found")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT) // TODO OR delete only permission
    public Response deleteCsafEntity(
            @Parameter(description = "The csafEntryId of the CSAF source to delete", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") String csafEntryId) {
        try (QueryManager qm = new QueryManager()) {

            final CsafSourceEntity csafEntity = qm.getObjectById(CsafSourceEntity.class, csafEntryId);
            if (csafEntity != null) {
                qm.delete(csafEntity);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The csafEntryId of the CSAF source could not be found.").build();
            }
        }
    }

    @GET
    @Path("/providers/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF providers", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF providers", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF entities", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafSourceEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response getCsafProviders() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getCsafSources(false, false);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Path("/providers/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new CSAF provider", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF provider", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "An provider with the specified identifier already exists")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response createCsafProvider(CsafSourceEntity jsonEntity) {
        try (QueryManager qm = new QueryManager()) {
            final CsafSourceEntity csafEntity = qm.createCsafSource(jsonEntity.getName(), jsonEntity.getUrl(),
                    jsonEntity.isEnabled(), false);
            return Response.status(Response.Status.CREATED).entity(csafEntity).build();
        } catch (Exception e) {
            return Response.status(Response.Status.CONFLICT).build();
        }
    }

    @POST
    @Path("/providers/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF provider", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF provider", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The csafEntityId of the provider could not be found")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT) // TODO create update only permission
    public Response updateCsafProvider(CsafSourceEntity jsonEntity) {
        try (QueryManager qm = new QueryManager()) {
            var csafEntity = qm.updateCsafSource(jsonEntity);
            if(csafEntity == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The ID of the provider could not be found.").build();
            }
            return Response.ok(csafEntity).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("The specified CSAF provider could not be updated").build();
        }
    }

    @GET
    @Path("/discoveries/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of discovered CSAF sources", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of discovered CSAF sources", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of discovered CSAF sources", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafSourceEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response getDiscoveredCsafSources() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            var results = qm.getCsafSources(false, true);

            return Response.ok(results.getObjects()).header(TOTAL_COUNT_HEADER, results.getTotal()).build();
        }
    }

    @GET
    @Path("/documents/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF documents", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF documents", content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafDocumentEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response getCsafDocuments(@QueryParam("searchText") String searchText, @QueryParam("pageSize") int pageSize, @QueryParam("pageNumber") int pageNumber, @QueryParam("sortName") String sortName, @QueryParam("sortOrder") String sortOrder) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            var results = qm.searchCsafDocuments(searchText, pageSize, pageNumber, sortName, sortOrder);
            return Response.ok(results).build();
        }
    }

    @POST
    @Path("/documents/")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.TEXT_PLAIN)
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    @Operation(summary = "Upload a new CSAF document", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The created CSAF document", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A repository with the specified identifier already exists")
    })
    public Response uploadCsafDocument(
            @FormDataParam("file") InputStream uploadStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail
    ) {
        try (var qm = new QueryManager();
             var uploadBuffer = new ByteArrayOutputStream()) {
            uploadStream.transferTo(uploadBuffer);
            String content = uploadBuffer.toString();

            // We do not have access to the complete CSAF library in the api server, but we do a quick
            // sanity check to ensure the file is a JSON and contains required CSAF fields for computing
            // the ID
            var doc = new ObjectMapper().readTree(content);
            var publisherNamespace = doc.get("document").get("publisher").get("namespace").asText();
            var trackingID = doc.get("document").get("tracking").get("id").asText();
            var trackingVersion = doc.get("document").get("tracking").get("version").asText();
            var title = doc.get("document").get("title").asText();

            // Create a new CSAF document that we have already "seen" and was just fetched
            final var csaf = new CsafDocumentEntity();
            csaf.setName(title);
            csaf.setUrl(fileDetail.getFileName());
            csaf.setContent(content);
            csaf.setLastFetched(Instant.now());
            csaf.setPublisherNamespace(publisherNamespace);
            csaf.setTrackingID(trackingID);
            csaf.setTrackingVersion(trackingVersion);
            csaf.setSeen(true);

            // Sync the document into the database, replacing an older version with the same combination
            // of tracking ID and publisher namespace if necessary
            qm.synchronizeCsafDocument(csaf);
            return Response.ok("File uploaded successfully: " + fileDetail.getFileName()).build();
        } catch (IOException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("File upload failed").build();
        }
    }

    @POST
    @Path("/documents/seen/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Mark a CSAF document as seen", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF document marked seen successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF document could not be found")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response toggleCsafDocumentSeen(
            @Parameter(description = "The id of the CSAF document to mark as seen", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("id") String id) {

        try (QueryManager qm = new QueryManager()) {
            final CsafDocumentEntity csafEntity = qm.getObjectById(CsafDocumentEntity.class,
                    id);
            if (csafEntity != null) {
                qm.toggleCsafDocumentSeen(csafEntity);
                return Response.ok(csafEntity).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).
                        entity("The id of the CSAF document could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/documents/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a CSAF source", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF source removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF source could not be found")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT) // TODO OR delete only permission
    public Response deleteCsafDocument(
            @Parameter(description = "The csafEntryId of the CSAF source to delete", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") String csafEntryId) {

        try (QueryManager qm = new QueryManager()) {
            final CsafDocumentEntity csafEntity = qm.getObjectById(CsafDocumentEntity.class,
                    csafEntryId);
            if (csafEntity != null) {
                qm.delete(csafEntity);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).
                        entity("The csafEntryId of the CSAF source could not be found.").build();
            }
        }
    }

    @GET
    @Path("/documents/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(summary = "Returns the contents of a CSAF document", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The content of a document"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.CSAF_MANAGEMENT)
    public Response getCsafDocumentContents(@Parameter(description = "The csafEntryId of the CSAF document to view", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") String csafEntryId) {
        try (QueryManager qm = new QueryManager()) {
            final var csafEntity = qm.getObjectById(CsafDocumentEntity.class, csafEntryId);

            if(csafEntity == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The requested CSAF document could not be found.").build();
            } else {
                return Response.ok(csafEntity.getContent()).build();
            }
        }
    }

    public static String computeDocumentId(String publisherNamespace, String trackingID) throws NoSuchAlgorithmException {
        var digest = MessageDigest.getInstance("SHA-256");

        return "CSAF-" + Hex.encodeHexString(
                digest.digest(
                        publisherNamespace.getBytes()
                )).substring(0, 8) + "-" + trackingID;
    }

}
