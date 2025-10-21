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
package org.dependencytrack.resources.v2;

import alpine.common.logging.Logger;
import alpine.server.auth.PermissionRequired;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.datasource.vuln.csaf.CsafSource;
import org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs;
import org.dependencytrack.datasource.vuln.csaf.SourcesManager;
import org.dependencytrack.event.CsafMirrorEvent;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.validation.ValidDomainValidator;
import org.dependencytrack.model.validation.ValidURLValidator;
import org.dependencytrack.plugin.ConfigRegistryImpl;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.tasks.CsafMirrorTask;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Predicate;

import static org.dependencytrack.resources.v2.CsafSourceConfigProvider.getCsafSourceByIdFromConfig;
import static org.dependencytrack.resources.v2.CsafSourceConfigProvider.updateSourcesInConfig;

/**
 * Resource for vulnerability policies.
 */
@Path("/csaf")
@Tag(name = "csaf")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
@Provider
public class CsafResource extends AbstractApiResource {
    private static final Logger LOGGER = Logger.getLogger(CsafResource.class);

    private static final ValidDomainValidator DOMAIN_VALIDATOR = new ValidDomainValidator();
    private static final ValidURLValidator URL_VALIDATOR = new ValidURLValidator();

    @POST
    @Path("/trigger-mirror/")
    @Operation(summary = "Triggers the CSAF mirror task manually", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "The CSAF mirror task has been triggered"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE)
    public Response triggerMirror() {
        LOGGER.info("Triggering CSAF mirror task manually");

        var mirror = new CsafMirrorTask();
        mirror.inform(new CsafMirrorEvent());

        return Response.accepted().build();
    }

    @GET
    @Path("/aggregators/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF aggregators", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_READ</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF entities", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF entities", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafSource.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_READ)
    public Response listCsafAggregators(@QueryParam("searchText") String searchText) {
        return listSources(searchText, true, false);
    }

    @PUT
    @Path("/aggregators/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new CSAF aggregator", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_CREATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF aggregator", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "400", description = "Invalid domain or url"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "An aggregator with the specified URL already exists")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_CREATE)
    public Response createCsafAggregator(CsafSource source) {
        return createCsafSource(source, true);
    }

    @POST
    @Path("/aggregators/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF aggregator", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF aggregator", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "400", description = "Invalid domain or url"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The ID of the aggregator could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE)
    public Response updateCsafAggregator(CsafSource source) {
        return updateCsafSource(source, true);
    }

    @DELETE
    @Path("/aggregators/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a CSAF aggregator", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_DELETE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF source removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF source could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_DELETE)
    public Response deleteCsafEntity(
            @Parameter(description = "The ID of the CSAF source to delete", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") int csafEntryId) {
        return deleteCsafSource(csafEntryId);
    }

    @GET
    @Path("/providers/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF providers", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_READ</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF providers", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF entities", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafSource.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_READ)
    public Response getCsafProviders() {
        return listSources(null, false, false);
    }

    @PUT
    @Path("/providers/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new CSAF provider", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_CREATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF provider", content = @Content(schema = @Schema(implementation = CsafSource.class))),
            @ApiResponse(responseCode = "400", description = "Invalid domain or url"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "An provider with the specified identifier already exists")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_CREATE)
    public Response createCsafProvider(CsafSource source) {
        return createCsafSource(source, false);
    }

    @POST
    @Path("/providers/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF provider", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF provider", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "400", description = "Invalid domain or url"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The ID of the provider could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE)
    public Response updateCsafProvider(CsafSource source) {
        return updateCsafSource(source, false);
    }

    @GET
    @Path("/discoveries/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of discovered CSAF sources", description = "<p>Requires permission <strong>VULNERABILITY_MANAGEMENT_READ</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of discovered CSAF sources", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of discovered CSAF sources", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafSource.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_READ)
    public Response getDiscoveredCsafSources() {
        return listSources("", false, true);
    }

    /**
     * Returns a list of CSAF sources from the configuration, filtered by the
     * provided predicate.
     *
     * @param filter the predicate to filter the sources
     * @return a list of CSAF sources
     */
    private static List<CsafSource> getCsafSourcesFromConfig(@Nullable Predicate<CsafSource> filter) {
        if (filter == null) {
            filter = s -> true;
        }

        try {
            var config = ConfigRegistryImpl.forExtension("vuln.datasource", "csaf");
            var sourcesConfig = config.getValue(CsafVulnDataSourceConfigs.CONFIG_SOURCES);
            return SourcesManager
                    .deserializeSources(new ObjectMapper().registerModule(new JavaTimeModule()), sourcesConfig).stream()
                    .filter(filter).toList();
        } catch (NoSuchElementException e) {
            return new ArrayList<>();
        }
    }

    /**
     * Returns a list of CSAF sources from the configuration, filtered by the
     * provided parameters.
     *
     * @param searchText   a search text to filter the sources by name or URL
     * @param isAggregator whether to include only aggregators
     * @param isDiscovery  whether to include only discovered sources
     * @return a Response containing the list of CSAF sources
     */
    private static Response listSources(String searchText, Boolean isAggregator, Boolean isDiscovery) {
        var sources = getCsafSourcesFromConfig(
                filter -> filter.isAggregator() == isAggregator && filter.isDiscovered() == isDiscovery &&
                        ((searchText == null || searchText.isEmpty())
                                || (filter.getName().toLowerCase().contains(searchText.toLowerCase()) ||
                                        filter.getUrl().toLowerCase().contains(searchText.toLowerCase()))));

        return Response.ok(sources).header(TOTAL_COUNT_HEADER, sources.size()).build();
    }

    /**
     * Creates a new CSAF source, either an aggregator or a provider.
     *
     * @param source       the CSAF source to create
     * @param isAggregator whether the source is an aggregator (true) or a provider
     *                     (false)
     * @return a Response indicating the result of the operation
     */
    private static Response createCsafSource(CsafSource source, Boolean isAggregator) {
        // Validate URL (which can either be a domain or a full URL)
        if (!DOMAIN_VALIDATOR.isValid(source.getUrl(), null) &&
                !URL_VALIDATOR.isValid(source.getUrl(), null)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid domain or url").build();
        }

        // Fetch existing sources
        var sources = new ArrayList<>(getCsafSourcesFromConfig(filter -> true));

        // Ensure that the new source does not already exist, by the URL
        if (sources.stream().anyMatch(s -> s.getUrl().equalsIgnoreCase(source.getUrl()))) {
            return Response.status(Response.Status.CONFLICT)
                    .entity("An aggregator with the specified URL already exists").build();
        }

        // Compute globally unique ID
        int newId = sources.stream()
                .mapToInt(CsafSource::getId)
                .max()
                .orElse(-1) + 1;

        // Add the new source to the list. Make sure that the aggregator flag is set
        // appropriately.
        source.setAggregator(isAggregator);
        source.setId(newId);
        source.setDomain(DOMAIN_VALIDATOR.isValid(source.getUrl(), null));
        sources.add(source);

        // Update config
        updateSourcesInConfig(sources);

        return Response.status(Response.Status.CREATED).entity(source).build();
    }

    /**
     * Updates a CSAF source, either an aggregator or a provider.
     *
     * @param source       the CSAF source to update
     * @param isAggregator whether the source is an aggregator (true) or a provider
     *                     (false)
     * @return a Response indicating the result of the operation
     */
    private static Response updateCsafSource(CsafSource source, Boolean isAggregator) {
        // Validate URL (which can either be a domain or a full URL)
        if (!DOMAIN_VALIDATOR.isValid(source.getUrl(), null) &&
                !URL_VALIDATOR.isValid(source.getUrl(), null)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid domain or url").build();
        }

        // Fetch an existing source and look for the one to update
        var sources = getCsafSourcesFromConfig(filter -> true);
        var existingSource = getCsafSourceByIdFromConfig(sources, source.getId());
        if (existingSource == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("The ID of the aggregator could not be found.").build();
        }

        // Update the existing source
        existingSource.setName(source.getName());
        existingSource.setEnabled(source.isEnabled());
        existingSource.setUrl(source.getUrl());
        existingSource.setAggregator(isAggregator);
        existingSource.setDomain(DOMAIN_VALIDATOR.isValid(source.getUrl(), null));
        existingSource.setDiscovered(source.isDiscovered());
        existingSource.setLastFetched(source.getLastFetched());

        // Update config
        updateSourcesInConfig(sources);

        return Response.ok(existingSource).build();
    }

    /**
     * Deletes a CSAF source, either an aggregator or a provider.
     *
     * @param id the ID of the CSAF source to delete
     * @return a Response indicating the result of the operation
     */
    private static Response deleteCsafSource(int id) {
        // Fetch existing aggregators and look for the one to delete
        var sources = new ArrayList<>(getCsafSourcesFromConfig(null));
        var source = getCsafSourceByIdFromConfig(sources, id);
        if (source == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("The ID of the source could not be found.").build();
        }

        // Remove the aggregator from the list
        sources.remove(source);

        // Update config
        updateSourcesInConfig(sources);

        return Response.status(Response.Status.NO_CONTENT).build();
    }

}
