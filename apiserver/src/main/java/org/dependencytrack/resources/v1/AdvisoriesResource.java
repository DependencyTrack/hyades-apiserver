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
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import io.csaf.retrieval.RetrievedDocument;
import org.dependencytrack.datasource.vuln.csaf.CsafSource;
import org.dependencytrack.datasource.vuln.csaf.ModelConverter;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.model.VulnerableSoftware;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Instant;

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.resources.v1.FindingResource.MEDIA_TYPE_SARIF_JSON;

/**
 * JAX-RS resources for advisories.
 *
 * @author Lawrence Dean
 * @since TODO set version
 */
@Path("/v1/advisories")
@Tag(name = "advisories")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class AdvisoriesResource extends AbstractApiResource {
    private static final Logger LOGGER = Logger.getLogger(AdvisoriesResource.class);

    @GET
    @Produces({ MediaType.APPLICATION_JSON, MEDIA_TYPE_SARIF_JSON })
    @Operation(summary = "Returns a list of all advisories", description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of all advisories for a specific project, or a SARIF file", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of advisories", schema = @Schema(format = "integer")), content = {
                    @Content(array = @ArraySchema(schema = @Schema(implementation = AdvisoryDao.AdvisoryInProjectRow.class)), mediaType = MediaType.APPLICATION_JSON),
                    @Content(schema = @Schema(type = "string"), mediaType = MEDIA_TYPE_SARIF_JSON)
            }),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to advisories prohibited", content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAllAdvisories(@QueryParam("format") String format,
            @QueryParam("searchText") String searchText) {
        // Normalize parameters: trim and treat empty as null so DAO SQL conditional
        // behaves predictably
        final String searchParam = (searchText == null || searchText.trim().isEmpty()) ? null
                : searchText.trim();
        final String formatParam = (format == null || format.trim().isEmpty()) ? null : format.trim();

        List<AdvisoryDao.AdvisoryDetailRow> advisoryRows = withJdbiHandle(getAlpineRequest(),
                handle -> handle.attach(AdvisoryDao.class).getAllAdvisories(formatParam, searchParam));
        final long totalCount = withJdbiHandle(getAlpineRequest(), handle -> handle.attach(AdvisoryDao.class)
                .getTotalAdvisories(formatParam, searchParam));
        return Response.ok(advisoryRows.stream().toList()).header(TOTAL_COUNT_HEADER, totalCount).build();
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.TEXT_PLAIN)
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE)
    @Operation(summary = "Upload an advisory document", description = "<p>Uploads and processes an advisory document. Currently only CSAF format is supported.</p>"
            +
            "<p>Requires permission <strong>VULNERABILITY_ANALYSIS_CREATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Advisory uploaded and processed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid format or malformed document"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "File upload failed")
    })
    public Response uploadAdvisory(
            @Parameter(description = "The format of the advisory document (currently only 'CSAF' is supported)", required = true, schema = @Schema(allowableValues = {
                    "CSAF" })) @QueryParam("format") String format,
            @Parameter(description = "The advisory document file to upload", required = true) @FormDataParam("file") InputStream uploadStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail) {
        try (var qm = new QueryManager(); var uploadBuffer = new ByteArrayOutputStream()) {
            uploadStream.transferTo(uploadBuffer);
            String content = uploadBuffer.toString();

            // Process-format-specific upload
            return switch (format) {
                case "CSAF" -> processCsafDocument(content, fileDetail.getFileName(), qm);
                default -> Response.status(Response.Status.BAD_REQUEST)
                        .entity("Unsupported format: " + format).build();
            };
        } catch (IOException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("File upload failed").build();
        }
    }

    /**
     * Process CSAF document content and synchronize advisory/vulnerabilities.
     * Returns a JAX-RS Response indicating success or error.
     *
     * @param content  the CSAF document content
     * @param fileName the name of the uploaded file
     * @param qm       the QueryManager to use for persistence
     * @return a JAX-RS Response indicating success or error
     */
    private Response processCsafDocument(String content, String fileName, QueryManager qm) {
        final var result = RetrievedDocument.fromJson(content, fileName);
        if (result.isFailure()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("The uploaded file is not a valid CSAF document: " +
                            (result.exceptionOrNull() != null
                                    ? result.exceptionOrNull().getMessage()
                                    : null))
                    .build();
        }
        assert result.getOrNull() != null;
        final var doc = result.getOrNull().getJson();
        final var publisher = doc.getDocument().getPublisher().getNamespace().toString();

        // Create a new advisory that we have already "seen" and was just fetched
        final var advisory = new Advisory();
        advisory.setTitle(doc.getDocument().getTitle());
        advisory.setUrl(fileName);
        advisory.setContent(content);
        advisory.setLastFetched(Instant.now());
        advisory.setPublisher(publisher);
        advisory.setName(doc.getDocument().getTracking().getId());
        advisory.setVersion(doc.getDocument().getTracking().getVersion());
        advisory.setFormat("CSAF");
        advisory.setSeen(true);

        // Create a pseudo-source populated by the information we have
        var manual = new CsafSource();
        manual.setDomain(true);
        manual.setUrl(URI.create(publisher).getHost());
        manual.setName(publisher);

        final var bov = ModelConverter.convert(result, manual);
        if (bov == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Could not extract vulnerability information").build();
        }

        for (final var v : bov.getVulnerabilitiesList()) {
            final Vulnerability vuln = BovModelConverter.convert(bov, v, true);
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            LOGGER.debug("Synchronizing vulnerability " + vuln.getVulnId());
            final Vulnerability persistentVuln = qm.synchronizeVulnerability(vuln, false);
            qm.synchronizeVulnerableSoftware(persistentVuln, vsList, Vulnerability.Source.CSAF);

            advisory.addVulnerability(persistentVuln);
        }

        // Sync the document into the database, replacing an older version with the same
        // combination of tracking ID and publisher namespace if necessary
        qm.synchronizeAdvisory(advisory);

        return Response.ok("File uploaded successfully: " + fileName).build();
    }

    @DELETE
    @Path("/{advisoryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes an advisory", description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Advisory removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The advisory could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE)
    public Response deleteAdvisory(@PathParam("advisoryId") String advisoryId) {
        try (QueryManager qm = new QueryManager()) {
            final Advisory entity = qm.getObjectById(Advisory.class, advisoryId);
            if (entity != null) {
                qm.delete(entity);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The advisory could not be found.").build();
            }
        }
    }

    @POST
    @Path("/seen/{advisoryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Marks an advisory as seen", description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Advisory marked as seen successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The advisory could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE)
    public Response markAdvisoryAsSeen(@PathParam("advisoryId") String advisoryId) {
        try (QueryManager qm = new QueryManager()) {
            final Advisory entity = qm.getObjectById(Advisory.class, advisoryId);
            if (entity != null) {
                entity.setSeen(true);
                qm.persist(entity);
                return Response.ok(entity).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The advisory could not be found.").build();
            }
        }
    }

    @GET
    @Path("/{advisoryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns the details of an advisory", description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS_READ</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Details of given advisory"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_READ)
    public Response getAdvisoryById(
            @Parameter(description = "The ID of the advisory to view", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("advisoryId") String advisoryId) {
        try (QueryManager qm = new QueryManager()) {
            final var advisoryEntity = qm.getObjectById(Advisory.class, advisoryId);

            if (advisoryEntity == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The requested advisory could not be found.")
                        .build();
            } else {
                List<AdvisoryDao.ProjectRow> affectedProjects = withJdbiHandle(getAlpineRequest(),
                        handle -> handle.attach(AdvisoryDao.class)
                                .getProjectsByAdvisory(advisoryEntity.getId()));

                List<AdvisoryDao.VulnerabilityRow> vulnerabilities = withJdbiHandle(getAlpineRequest(),
                        handle -> handle.attach(AdvisoryDao.class)
                                .getVulnerabilitiesByAdvisory(advisoryEntity.getId()));

                Long numAffectedComponentsBoxed = withJdbiHandle(getAlpineRequest(),
                        handle -> handle.attach(AdvisoryDao.class)
                                .getAmountFindingsTotal(advisoryEntity.getId()));
                long numAffectedComponents = numAffectedComponentsBoxed != null
                        ? numAffectedComponentsBoxed
                        : 0L;

                return Response.ok(new AdvisoryDao.AdvisoryResult(
                        advisoryEntity,
                        affectedProjects,
                        numAffectedComponents,
                        vulnerabilities)).build();
            }
        }
    }

    @GET
    @Path("/project/{uuid}")
    @Produces({ MediaType.APPLICATION_JSON, MEDIA_TYPE_SARIF_JSON })
    @Operation(summary = "Returns a list of matched advisories on a given project", description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of all advisories for a specific project, or a SARIF file", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of advisories", schema = @Schema(format = "integer")), content = {
                    @Content(array = @ArraySchema(schema = @Schema(implementation = AdvisoryDao.AdvisoryInProjectRow.class)), mediaType = MediaType.APPLICATION_JSON),
                    @Content(schema = @Schema(type = "string"), mediaType = MEDIA_TYPE_SARIF_JSON)
            }),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the requested project is forbidden", content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAdvisoriesByProject(
            @Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true) @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Optionally includes suppressed advisories") @QueryParam("suppressed") boolean suppressed,
            @Parameter(description = "Optionally limit advisories to specific sources of vulnerability intelligence") @QueryParam("source") Vulnerability.Source source,
            @HeaderParam("accept") String acceptHeader) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                requireAccess(qm, project);

                List<AdvisoryDao.AdvisoryInProjectRow> advisoryWithFindingRows = withJdbiHandle(
                        getAlpineRequest(),
                        handle -> handle.attach(AdvisoryDao.class)
                                .getAdvisoriesWithFindingsByProject(project.getId(),
                                        suppressed));
                final long totalCount = advisoryWithFindingRows.size();

                return Response.ok(advisoryWithFindingRows.stream().toList())
                        .header(TOTAL_COUNT_HEADER, totalCount).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/project/{projectId}/advisory/{advisoryId}")
    @Produces({ MediaType.APPLICATION_JSON })
    @Operation(summary = "Returns a list of findings associated to project x advisory", description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of all advisory findings for a specific project and advisory", content = {
                    @Content(array = @ArraySchema(schema = @Schema(implementation = AdvisoryDao.ProjectAdvisoryFindingRow.class)), mediaType = MediaType.APPLICATION_JSON),
            }),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the requested project is forbidden", content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project or advisory could not be found")
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProjectAdvisory(
            @Parameter(description = "The ID of the project", schema = @Schema(type = "string"), required = true) @PathParam("projectId") long projectId,
            @Parameter(description = "The advisoryId", schema = @Schema(type = "string"), required = true) @PathParam("advisoryId") long advisoryId,
            @HeaderParam("accept") String acceptHeader) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            LOGGER.info("Querying for " + projectId + " :: " + advisoryId);
            List<AdvisoryDao.ProjectAdvisoryFindingRow> advisoryRows = withJdbiHandle(getAlpineRequest(),
                    handle -> handle.attach(AdvisoryDao.class)
                            .getFindingsByProjectAdvisory(projectId, advisoryId));
            final long totalCount = advisoryRows.size();
            LOGGER.info("retrieved size " + totalCount);

            return Response.ok(advisoryRows.stream().toList()).header(TOTAL_COUNT_HEADER, totalCount)
                    .build();
        }
    }
}
