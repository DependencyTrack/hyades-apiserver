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
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;

import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.util.InternalComponentIdentifier;

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
import java.util.List;

/**
 * JAX-RS resources for processing crypto assets.
 *
 * @author Nicklas Körtge
 * @since 4.5.0
 */

@Path("/v1/crypto")
@Tag(name = "crypto")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CryptoAssetsResource extends AlpineResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all crypto assets of a specific project",
            description = "Returns a list of all crypto assets of a specific project"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "A list of all crypto assets for a given project",
            headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of crypto assets", schema = @Schema(format = "integer")),
            content = @Content(array = @ArraySchema(schema = @Schema(implementation = Component.class)))
        ),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access to the specified crypto asset is forbidden"),
        @ApiResponse(responseCode = "404", description = "The crypto asset could not be found.")
    })
    public Response getAllCryptoAssetsOfAProject(@PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {

            final Project project = qm.getObjectByUuid(Project.class, uuid);

            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final List<Component> cryptoAssets = qm.getAllCryptoAssets(project);
                    return Response.ok(cryptoAssets).header(TOTAL_COUNT_HEADER, cryptoAssets.size()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        } catch (Error e) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }
  
    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Returns a specific crypto asset",
        description = "Returns a specific crypto asset given by its uuid"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "A crypto asset",
            content = @Content(schema = @Schema(implementation = Component.class))
        ),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access to the specified crypto asset is forbidden"),
        @ApiResponse(responseCode = "404", description = "The crypto asset could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getCryptoAssetByUuid(
            @Parameter(description = "The UUID of the component to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null && component.getClassifier() == Classifier.CRYPTOGRAPHIC_ASSET) {
                final Project project = component.getProject();
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    qm.getPersistenceManager().getFetchPlan().setMaxFetchDepth(3);
                    final Component asset = qm.detach(Component.class, component.getId()); // TODO: Force project to be loaded. It should be anyway, but JDO seems to be having issues here.
                    return Response.ok(asset).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified crypto asset is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The crypto asset could not be found.").build();
            }
        }
    }

    @GET
    @Path("/identity")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Returns a a list of crypto asset that have the specified identity.",
        description = "Returns a a list of crypto asset that have the specified identity."
    )
    @PaginatedApi
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "A list of all components for a given project",
            headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of crypto assets", schema = @Schema(format = "integer")),
            content = @Content(array = @ArraySchema(schema = @Schema(implementation = Component.class)))
        ),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentByIdentity(
        @Parameter(description = "The type of the crypto assets to retrieve")
        @QueryParam("assetType") String assetType){
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            String assetTypeStr = StringUtils.trimToNull(assetType);
            final ComponentIdentity identity = new ComponentIdentity(assetTypeStr != null ? AssetType.valueOf(assetTypeStr) : null);
            final PaginatedResult result = qm.getCryptoAssets(identity);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Path("/project/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Creates a new crypto asset",
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
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response createComponent(@PathParam("uuid") String uuid, Component jsonComponent) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonComponent, "author"),
                validator.validateProperty(jsonComponent, "publisher"),
                validator.validateProperty(jsonComponent, "name"),
                validator.validateProperty(jsonComponent, "version"),
                validator.validateProperty(jsonComponent, "group"),
                validator.validateProperty(jsonComponent, "description"),
                validator.validateProperty(jsonComponent, "license"),
                validator.validateProperty(jsonComponent, "filename"),
                validator.validateProperty(jsonComponent, "classifier"),
                validator.validateProperty(jsonComponent, "cpe"),
                validator.validateProperty(jsonComponent, "swidTagId"),
                validator.validateProperty(jsonComponent, "copyright"),
                validator.validateProperty(jsonComponent, "md5"),
                validator.validateProperty(jsonComponent, "sha1"),
                validator.validateProperty(jsonComponent, "sha256"),
                validator.validateProperty(jsonComponent, "sha384"),
                validator.validateProperty(jsonComponent, "sha512"),
                validator.validateProperty(jsonComponent, "sha3_256"),
                validator.validateProperty(jsonComponent, "sha3_384"),
                validator.validateProperty(jsonComponent, "sha3_512"),
                validator.validateProperty(jsonComponent, "cryptoAssetProperties")
        );

        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            if (! qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }
            if (jsonComponent.getClassifier() != Classifier.CRYPTOGRAPHIC_ASSET) {
                return Response.status(Response.Status.BAD_REQUEST).entity("The component you provided is not a crypto asset").build();
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

            if (jsonComponent.getCryptoAssetProperties() != null) {
                component.setCryptoAssetProperties(jsonComponent.getCryptoAssetProperties());
            } else {
                return Response.status(Response.Status.BAD_REQUEST).entity("No data for crypto asset properties provided").build();
            }

            if (resolvedLicense != null) {
                component.setLicense(null);
                component.setResolvedLicense(resolvedLicense);
            } else {
                component.setLicense(StringUtils.trimToNull(jsonComponent.getLicense()));
                component.setResolvedLicense(null);
            }
            component.setNotes(StringUtils.trimToNull(jsonComponent.getNotes()));

            component = qm.createComponent(component, true);
            return Response.status(Response.Status.CREATED).entity(component).build();
        }
    }


    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Updates a crypto assets",
        description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
        @ApiResponse(
                responseCode = "200",
                description = "The updated component",
                content = @Content(schema = @Schema(implementation = Component.class))
        ),
        @ApiResponse(responseCode = "400", description = "No data for crypto asset properties provided"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
        @ApiResponse(responseCode = "404", description = "The UUID of the component could not be found"),
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response updateCryptoAsset(Component jsonComponent) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonComponent, "name"),
                validator.validateProperty(jsonComponent, "version"),
                validator.validateProperty(jsonComponent, "group"),
                validator.validateProperty(jsonComponent, "description"),
                validator.validateProperty(jsonComponent, "license"),
                validator.validateProperty(jsonComponent, "filename"),
                validator.validateProperty(jsonComponent, "classifier"),
                validator.validateProperty(jsonComponent, "cpe"),
                validator.validateProperty(jsonComponent, "swidTagId"),
                validator.validateProperty(jsonComponent, "copyright"),
                validator.validateProperty(jsonComponent, "md5"),
                validator.validateProperty(jsonComponent, "sha1"),
                validator.validateProperty(jsonComponent, "sha256"),
                validator.validateProperty(jsonComponent, "sha512"),
                validator.validateProperty(jsonComponent, "sha3_256"),
                validator.validateProperty(jsonComponent, "sha3_512"),
                validator.validateProperty(jsonComponent, "cryptoAssetProperties")
        );
        try (QueryManager qm = new QueryManager()) {
            Component component = qm.getObjectByUuid(Component.class, jsonComponent.getUuid());
            if (component != null) {
                if (! qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified crypto asset is forbidden").build();
                }
                if (jsonComponent.getClassifier() != Classifier.CRYPTOGRAPHIC_ASSET) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The component you provided is not a crypto asset").build();
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

                if (jsonComponent.getCryptoAssetProperties() != null) {
                    component.setCryptoAssetProperties(jsonComponent.getCryptoAssetProperties());
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity("No data for crypto asset properties provided").build();
                }

                final License resolvedLicense = qm.getLicense(jsonComponent.getLicense());
                if (resolvedLicense != null) {
                    component.setLicense(null);
                    component.setResolvedLicense(resolvedLicense);
                } else {
                    component.setLicense(StringUtils.trimToNull(jsonComponent.getLicense()));
                    component.setResolvedLicense(null);
                }
                component.setNotes(StringUtils.trimToNull(jsonComponent.getNotes()));

                component = qm.updateComponent(component, true);
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
        summary = "Deletes a crypto asset",
        description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "204", description = "Crypto asset removed successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access to the specified crypto asset is forbidden"),
        @ApiResponse(responseCode = "404", description = "The UUID of the crypto asset could not be found")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE})
    public Response deleteComponent(
        @Parameter(description = "The UUID of the component to delete", schema = @Schema(format = "uuid"), required = true)
        @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid, Component.FetchGroup.ALL.name());
            if (component != null && component.getClassifier() == Classifier.CRYPTOGRAPHIC_ASSET) {
                if (! qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified crypto asset is forbidden").build();
                }
                qm.recursivelyDelete(component, false);
                //qm.commitSearchIndex(Component.class);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the crypto asset could not be found.").build();
            }
        }
    }
}
