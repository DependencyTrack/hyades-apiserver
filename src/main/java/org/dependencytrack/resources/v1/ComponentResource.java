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
import alpine.event.framework.Event;
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
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
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.componentmeta.ComponentProjection;
import org.dependencytrack.event.kafka.componentmeta.Handler;
import org.dependencytrack.event.kafka.componentmeta.HandlerFactory;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.PurlUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.event.kafka.componentmeta.IntegrityCheck.calculateIntegrityResult;
import static org.dependencytrack.model.FetchStatus.NOT_AVAILABLE;
import static org.dependencytrack.model.FetchStatus.PROCESSED;

/**
 * JAX-RS resources for processing components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/component")
@Tag(name = "component")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ComponentResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(ComponentResource.class);
    private final KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all components for a given project",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all components for a given project",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of components", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Component.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getAllComponents(
            @Parameter(description = "The UUID of the project to retrieve components for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Optionally exclude recent components so only outdated components are returned", required = false)
            @QueryParam("onlyOutdated") boolean onlyOutdated,
            @Parameter(description = "Optionally exclude transitive dependencies so only direct dependencies are returned", required = false)
            @QueryParam("onlyDirect") boolean onlyDirect) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final PaginatedResult result = qm.getComponents(project, true, onlyOutdated, onlyDirect);
                    return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific component",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A component",
                    content = @Content(schema = @Schema(implementation = Component.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentByUuid(
            @Parameter(description = "The UUID of the component to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Optionally includes third-party metadata about the component from external repositories")
            @QueryParam("includeRepositoryMetaData") boolean includeRepositoryMetaData,
            @QueryParam("includeIntegrityMetaData") boolean includeIntegrityMetaData) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                final Project project = component.getProject();
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final Component detachedComponent = qm.detach(Component.class, component.getId()); // TODO: Force project to be loaded. It should be anyway, but JDO seems to be having issues here.
                    if ((includeRepositoryMetaData || includeIntegrityMetaData) && detachedComponent.getPurl() != null) {
                        final RepositoryType type = RepositoryType.resolve(detachedComponent.getPurl());
                        if (RepositoryType.UNSUPPORTED != type) {
                            if (includeRepositoryMetaData) {
                                final RepositoryMetaComponent repoMetaComponent = qm.getRepositoryMetaComponent(type, detachedComponent.getPurl().getNamespace(), detachedComponent.getPurl().getName());
                                detachedComponent.setRepositoryMeta(repoMetaComponent);
                            }
                            if (includeIntegrityMetaData) {
                                detachedComponent.setComponentMetaInformation(qm.getMetaInformation(component.getUuid()));
                            }
                        }
                    }
                    return Response.ok(detachedComponent).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    @GET
    @Path("/integritymetadata")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = """
                    Provides the published date and hashes of the requested version of component,
                    as received from configured repositories for integrity analysis.""",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Integrity metadata of the component",
                    content = @Content(schema = @Schema(implementation = IntegrityMetaComponent.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The integrity meta information for the specified component cannot be found"),
            @ApiResponse(responseCode = "400", description = "The package url being queried for is invalid")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getIntegrityMetaComponent(
            @Parameter(description = "The package url of the component", required = true)
            @QueryParam("purl") String purl) {
        try {
            final PackageURL packageURL = new PackageURL(purl);
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                final RepositoryType type = RepositoryType.resolve(packageURL);
                if (RepositoryType.UNSUPPORTED == type) {
                    return Response.noContent().build();
                }
                final IntegrityMetaComponent result = qm.getIntegrityMetaComponent(packageURL.toString());
                if (result == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The integrity metadata for the specified component cannot be found.").build();
                } else {
                    //todo: future enhancement: provide pass-thru capability for component metadata not already present and being tracked
                    return Response.ok(result).build();
                }
            }
        } catch (MalformedPackageURLException e) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @GET
    @Path("/{uuid}/integritycheckstatus")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = """
                    Provides the integrity check status of component with provided UUID,
                    based on the configured repository for integrity analysis.""",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Integrity metadata of the component",
                    content = @Content(schema = @Schema(implementation = IntegrityAnalysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The integrity analysis information for the specified component cannot be found"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getIntegrityStatus(
            @Parameter(description = "UUID of the component for which integrity status information is needed", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final IntegrityAnalysis result = qm.getIntegrityAnalysisByComponentUuid(UUID.fromString(uuid));
            if (result == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The integrity status for the specified component cannot be found.").build();
            } else {
                //todo: future enhancement: provide pass-thru capability for component metadata not already present and being tracked
                return Response.ok(result).build();
            }
        }
    }

    @GET
    @Path("/identity")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of components that have the specified component identity. This resource accepts coordinates (group, name, version) or purl, cpe, or swidTagId",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of components that have the specified component identity",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of components", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Component.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentByIdentity(@Parameter(description = "The group of the component")
                                           @QueryParam("group") String group,
                                           @Parameter(description = "The name of the component")
                                           @QueryParam("name") String name,
                                           @Parameter(description = "The version of the component")
                                           @QueryParam("version") String version,
                                           @Parameter(description = "The purl of the component")
                                           @QueryParam("purl") String purl,
                                           @Parameter(description = "The cpe of the component")
                                           @QueryParam("cpe") String cpe,
                                           @Parameter(description = "The swidTagId of the component")
                                           @QueryParam("swidTagId") String swidTagId,
                                           @Parameter(description = "The project the component belongs to", schema = @Schema(format = "uuid"))
                                           @QueryParam("project") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            Project project = null;
            if (projectUuid != null) {
                project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
                }
                if (!qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            }
            PackageURL packageURL = null;
            if (purl != null) {
                try {
                    packageURL = new PackageURL(purl);
                } catch (MalformedPackageURLException e) {
                    // throw it away
                }
            }
            final ComponentIdentity identity = new ComponentIdentity(packageURL, StringUtils.trimToNull(cpe),
                    StringUtils.trimToNull(swidTagId), StringUtils.trimToNull(group), StringUtils.trimToNull(name),
                    StringUtils.trimToNull(version));
            if (identity.getGroup() == null && identity.getName() == null && identity.getVersion() == null
                    && identity.getPurl() == null && identity.getCpe() == null && identity.getSwidTagId() == null) {
                return Response.ok().header(TOTAL_COUNT_HEADER, 0).build();
            } else {
                final PaginatedResult result = qm.getComponents(identity, project, true);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
            }
        }
    }

    @GET
    @Path("/hash/{hash}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of components that have the specified hash value",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of components that have the specified hash value",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Component.class))),
                    headers = @Header(description = "The total number of components", name = TOTAL_COUNT_HEADER, schema = @Schema(format = "integer"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentByHash(
            @Parameter(description = "The MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, or BLAKE3 hash of the component to retrieve", required = true)
            @PathParam("hash") String hash) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getComponentByHash(hash);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Path("/project/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new component",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created component",
                    content = @Content(schema = @Schema(implementation = Component.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired({ Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE })
    public Response createComponent(@Parameter(description = "The UUID of the project to create a component for", schema = @Schema(format = "uuid"), required = true)
                                    @PathParam("uuid") @ValidUuid String uuid, Component jsonComponent) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonComponent, "author"),
                validator.validateProperty(jsonComponent, "publisher"),
                validator.validateProperty(jsonComponent, "name"),
                validator.validateProperty(jsonComponent, "version"),
                validator.validateProperty(jsonComponent, "group"),
                validator.validateProperty(jsonComponent, "description"),
                validator.validateProperty(jsonComponent, "license"),
                validator.validateProperty(jsonComponent, "licenseExpression"),
                validator.validateProperty(jsonComponent, "licenseUrl"),
                validator.validateProperty(jsonComponent, "filename"),
                validator.validateProperty(jsonComponent, "classifier"),
                validator.validateProperty(jsonComponent, "cpe"),
                validator.validateProperty(jsonComponent, "purl"),
                validator.validateProperty(jsonComponent, "swidTagId"),
                validator.validateProperty(jsonComponent, "copyright"),
                validator.validateProperty(jsonComponent, "md5"),
                validator.validateProperty(jsonComponent, "sha1"),
                validator.validateProperty(jsonComponent, "sha256"),
                validator.validateProperty(jsonComponent, "sha384"),
                validator.validateProperty(jsonComponent, "sha512"),
                validator.validateProperty(jsonComponent, "sha3_256"),
                validator.validateProperty(jsonComponent, "sha3_384"),
                validator.validateProperty(jsonComponent, "sha3_512")
        );

        try (QueryManager qm = new QueryManager()) {
            Component parent = null;
            if (jsonComponent.getParent() != null && jsonComponent.getParent().getUuid() != null) {
                parent = qm.getObjectByUuid(Component.class, jsonComponent.getParent().getUuid());
            }
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            if (!qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }
            final License resolvedLicense = qm.getLicense(jsonComponent.getLicense());
            Component component = new Component();
            component.setProject(project);
            component.setAuthor(StringUtils.trimToNull(jsonComponent.getAuthor()));
            component.setPublisher(StringUtils.trimToNull(jsonComponent.getPublisher()));
            component.setName(StringUtils.trimToNull(jsonComponent.getName()));
            component.setVersion(StringUtils.trimToNull(jsonComponent.getVersion()));
            component.setGroup(StringUtils.trimToNull(jsonComponent.getGroup()));
            component.setDescription(StringUtils.trimToNull(jsonComponent.getDescription()));
            component.setFilename(StringUtils.trimToNull(jsonComponent.getFilename()));
            component.setClassifier(jsonComponent.getClassifier());
            component.setPurl(jsonComponent.getPurl());
            component.setPurlCoordinates(PurlUtil.silentPurlCoordinatesOnly(jsonComponent.getPurl()));
            component.setInternal(new InternalComponentIdentifier().isInternal(component));
            component.setCpe(StringUtils.trimToNull(jsonComponent.getCpe()));
            component.setSwidTagId(StringUtils.trimToNull(jsonComponent.getSwidTagId()));
            component.setCopyright(StringUtils.trimToNull(jsonComponent.getCopyright()));
            component.setMd5(StringUtils.trimToNull(jsonComponent.getMd5()));
            component.setSha1(StringUtils.trimToNull(jsonComponent.getSha1()));
            component.setSha256(StringUtils.trimToNull(jsonComponent.getSha256()));
            component.setSha384(StringUtils.trimToNull(jsonComponent.getSha384()));
            component.setSha512(StringUtils.trimToNull(jsonComponent.getSha512()));
            component.setSha3_256(StringUtils.trimToNull(jsonComponent.getSha3_256()));
            component.setSha3_384(StringUtils.trimToNull(jsonComponent.getSha3_384()));
            component.setSha3_512(StringUtils.trimToNull(jsonComponent.getSha3_512()));
            if (resolvedLicense != null) {
                component.setLicense(null);
                component.setLicenseExpression(null);
                component.setLicenseUrl(StringUtils.trimToNull(jsonComponent.getLicenseUrl()));
                component.setResolvedLicense(resolvedLicense);
            } else if (StringUtils.isNotBlank(jsonComponent.getLicense())) {
                component.setLicense(StringUtils.trim(jsonComponent.getLicense()));
                component.setLicenseExpression(null);
                component.setLicenseUrl(StringUtils.trimToNull(jsonComponent.getLicenseUrl()));
                component.setResolvedLicense(null);
            } else if (StringUtils.isNotBlank(jsonComponent.getLicenseExpression())) {
                component.setLicense(null);
                component.setLicenseExpression(StringUtils.trim(jsonComponent.getLicenseExpression()));
                component.setLicenseUrl(null);
                component.setResolvedLicense(null);
            }
            component.setParent(parent);
            component.setNotes(StringUtils.trimToNull(jsonComponent.getNotes()));

            component = qm.createComponent(component, true);
            ComponentProjection componentProjection =
                    new ComponentProjection(component.getUuid(), component.getPurlCoordinates().toString(),
                            component.isInternal(), component.getPurl());
            try {
                Handler repoMetaHandler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION);
                IntegrityMetaComponent integrityMetaComponent = repoMetaHandler.handle();
                if (integrityMetaComponent != null && (integrityMetaComponent.getStatus() == PROCESSED || integrityMetaComponent.getStatus() == NOT_AVAILABLE)) {
                    calculateIntegrityResult(integrityMetaComponent, component, qm);
                }
            } catch (MalformedPackageURLException ex) {
                LOGGER.warn("Unable to process package url %s".formatted(componentProjection.purl()));
            }
            final var vulnAnalysisEvent = new ComponentVulnerabilityAnalysisEvent(UUID.randomUUID(), component, VulnerabilityAnalysisLevel.MANUAL_ANALYSIS, true);
            qm.createVulnerabilityScan(VulnerabilityScan.TargetType.COMPONENT, component.getUuid(), vulnAnalysisEvent.token().toString(), 1);
            kafkaEventDispatcher.dispatchEvent(vulnAnalysisEvent);
            return Response.status(Response.Status.CREATED).entity(component).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a component",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated component",
                    content = @Content(schema = @Schema(implementation = Component.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The UUID of the component could not be found"),
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response updateComponent(Component jsonComponent) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonComponent, "name"),
                validator.validateProperty(jsonComponent, "version"),
                validator.validateProperty(jsonComponent, "group"),
                validator.validateProperty(jsonComponent, "description"),
                validator.validateProperty(jsonComponent, "license"),
                validator.validateProperty(jsonComponent, "licenseExpression"),
                validator.validateProperty(jsonComponent, "licenseUrl"),
                validator.validateProperty(jsonComponent, "filename"),
                validator.validateProperty(jsonComponent, "classifier"),
                validator.validateProperty(jsonComponent, "cpe"),
                validator.validateProperty(jsonComponent, "purl"),
                validator.validateProperty(jsonComponent, "swidTagId"),
                validator.validateProperty(jsonComponent, "copyright"),
                validator.validateProperty(jsonComponent, "md5"),
                validator.validateProperty(jsonComponent, "sha1"),
                validator.validateProperty(jsonComponent, "sha256"),
                validator.validateProperty(jsonComponent, "sha512"),
                validator.validateProperty(jsonComponent, "sha3_256"),
                validator.validateProperty(jsonComponent, "sha3_512")
        );
        try (QueryManager qm = new QueryManager()) {
            Component component = qm.getObjectByUuid(Component.class, jsonComponent.getUuid());
            if (component != null) {
                if (!qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
                // Name cannot be empty or null - prevent it
                final String name = StringUtils.trimToNull(jsonComponent.getName());
                if (name != null) {
                    component.setName(name);
                }
                component.setAuthor(StringUtils.trimToNull(jsonComponent.getAuthor()));
                component.setPublisher(StringUtils.trimToNull(jsonComponent.getPublisher()));
                component.setVersion(StringUtils.trimToNull(jsonComponent.getVersion()));
                component.setGroup(StringUtils.trimToNull(jsonComponent.getGroup()));
                component.setDescription(StringUtils.trimToNull(jsonComponent.getDescription()));
                component.setFilename(StringUtils.trimToNull(jsonComponent.getFilename()));
                component.setClassifier(jsonComponent.getClassifier());
                component.setPurl(jsonComponent.getPurl());
                component.setPurlCoordinates(PurlUtil.silentPurlCoordinatesOnly(component.getPurl()));
                component.setInternal(new InternalComponentIdentifier().isInternal(component));
                component.setCpe(StringUtils.trimToNull(jsonComponent.getCpe()));
                component.setSwidTagId(StringUtils.trimToNull(jsonComponent.getSwidTagId()));
                component.setCopyright(StringUtils.trimToNull(jsonComponent.getCopyright()));
                component.setMd5(StringUtils.trimToNull(jsonComponent.getMd5()));
                component.setSha1(StringUtils.trimToNull(jsonComponent.getSha1()));
                component.setSha256(StringUtils.trimToNull(jsonComponent.getSha256()));
                component.setSha384(StringUtils.trimToNull(jsonComponent.getSha384()));
                component.setSha512(StringUtils.trimToNull(jsonComponent.getSha512()));
                component.setSha3_256(StringUtils.trimToNull(jsonComponent.getSha3_256()));
                component.setSha3_384(StringUtils.trimToNull(jsonComponent.getSha3_384()));
                component.setSha3_512(StringUtils.trimToNull(jsonComponent.getSha3_512()));
                component.setExternalReferences(jsonComponent.getExternalReferences());

                final License resolvedLicense = qm.getLicense(jsonComponent.getLicense());
                if (resolvedLicense != null) {
                    component.setLicense(null);
                    component.setLicenseExpression(null);
                    component.setLicenseUrl(StringUtils.trimToNull(jsonComponent.getLicenseUrl()));
                    component.setResolvedLicense(resolvedLicense);
                } else if (StringUtils.trimToNull(jsonComponent.getLicense()) != null) {
                    component.setLicense(StringUtils.trim(jsonComponent.getLicense()));
                    component.setLicenseExpression(null);
                    component.setLicenseUrl(StringUtils.trimToNull(jsonComponent.getLicenseUrl()));
                    component.setResolvedLicense(null);
                } else if (StringUtils.trimToNull(jsonComponent.getLicenseExpression()) != null) {
                    component.setLicense(null);
                    component.setLicenseExpression(StringUtils.trim(jsonComponent.getLicenseExpression()));
                    component.setLicenseUrl(null);
                    component.setResolvedLicense(null);
                } else {
                    component.setLicense(null);
                    component.setLicenseExpression(null);
                    component.setLicenseUrl(null);
                    component.setResolvedLicense(null);
                }
                component.setNotes(StringUtils.trimToNull(jsonComponent.getNotes()));

                component = qm.updateComponent(component, true);
                ComponentProjection componentProjection =
                        new ComponentProjection(component.getUuid(), component.getPurlCoordinates().toString(),
                                component.isInternal(), component.getPurl());
                try {

                    Handler repoMetaHandler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION);
                    IntegrityMetaComponent integrityMetaComponent = repoMetaHandler.handle();
                    if (integrityMetaComponent != null && (integrityMetaComponent.getStatus() == PROCESSED || integrityMetaComponent.getStatus() == NOT_AVAILABLE)) {
                        calculateIntegrityResult(integrityMetaComponent, component, qm);
                    }
                } catch (MalformedPackageURLException ex) {
                    LOGGER.warn("Unable to determine package url type for this purl %s".formatted(component.getPurl().getType()), ex);
                }
                final var vulnAnalysisEvent = new ComponentVulnerabilityAnalysisEvent(UUID.randomUUID(), component, VulnerabilityAnalysisLevel.MANUAL_ANALYSIS, false);
                qm.createVulnerabilityScan(VulnerabilityScan.TargetType.COMPONENT, component.getUuid(), vulnAnalysisEvent.token().toString(), 1);
                kafkaEventDispatcher.dispatchEvent(vulnAnalysisEvent);
                return Response.ok(component).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the component could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a component",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Component removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The UUID of the component could not be found")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE})
    public Response deleteComponent(
            @Parameter(description = "The UUID of the component to delete", schema = @Schema(format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid, Component.FetchGroup.ALL.name());
            if (component != null) {
                if (!qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
                qm.recursivelyDelete(component, false);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the component could not be found.").build();
            }
        }
    }

    @GET
    @Path("/internal/identify")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Requests the identification of internal components in the portfolio",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Identification requested successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_READ})
    public Response identifyInternalComponents() {
        Event.dispatch(new InternalComponentIdentificationEvent());
        return Response.status(Response.Status.NO_CONTENT).build();
    }

    @GET
    @Path("/project/{projectUuid}/dependencyGraph/{componentUuids}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the expanded dependency graph to every occurrence of a component",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The expanded dependency graph to every occurrence of a component",
                    content = @Content(schema = @Schema(type = "object"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "- The UUID of the project could not be found\n- The UUID of the component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getDependencyGraphForComponent(
            @Parameter(description = "The UUID of the project to get the expanded dependency graph for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid,
            @Parameter(description = "List of UUIDs of the components (separated by |) to get the expanded dependency graph for", required = true)
            @PathParam("componentUuids") @ValidUuid String componentUuids) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }

            if (!qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden.").build();
            }

            final String[] componentUuidsSplit = componentUuids.split("\\|");
            final List<Component> components = new ArrayList<>();
            for (String uuid : componentUuidsSplit) {
                final Component component = qm.getObjectByUuid(Component.class, uuid);
                if (component == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the component could not be found.").build();
                }
                components.add(component);
            }
            Map<String, Component> dependencyGraph = qm.getDependencyGraphForComponents(project, components);
            return Response.ok(dependencyGraph).build();
        }
    }
}
