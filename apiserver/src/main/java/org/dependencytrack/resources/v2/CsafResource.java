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
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.CsafApi;
import org.dependencytrack.api.v2.model.CsafSourceUpdateRequest;
import org.dependencytrack.api.v2.model.ListCsafSourcesResponse;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.datasource.vuln.csaf.CsafSource;
import org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs;
import org.dependencytrack.datasource.vuln.csaf.SourcesManager;
import org.dependencytrack.event.CsafMirrorEvent;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.model.validation.ValidDomainValidator;
import org.dependencytrack.model.validation.ValidURLValidator;
import org.dependencytrack.plugin.ConfigRegistryImpl;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.tasks.CsafMirrorTask;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Predicate;

/**
 * Resource for CSAF data source management.
 */
@Path("/")
public class CsafResource extends AbstractApiResource implements CsafApi {
    private static final Logger LOGGER = Logger.getLogger(CsafResource.class);

    private static final ValidDomainValidator DOMAIN_VALIDATOR = new ValidDomainValidator();
    private static final ValidURLValidator URL_VALIDATOR = new ValidURLValidator();

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE)
    public Response triggerCsafMirror() {
        LOGGER.info("Triggering CSAF mirror task manually");

        var mirror = new CsafMirrorTask();
        mirror.inform(new CsafMirrorEvent());

        return Response.accepted().build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_READ)
    public Response listCsafSources(String type, Boolean discovered, String searchText) {
        // Determine filter based on type parameter
        final Boolean isAggregatorFilter;
        final boolean isDiscoveredFilter;

        if ("aggregator".equalsIgnoreCase(type)) {
            isAggregatorFilter = true;
        } else if ("provider".equalsIgnoreCase(type)) {
            isAggregatorFilter = false;
        } else {
            isAggregatorFilter = null;
        }
        isDiscoveredFilter = discovered != null && discovered;

        var pluginSources = getPluginCsafSourcesFromConfig(
                source -> (isAggregatorFilter == null || source.isAggregator() == isAggregatorFilter)
                        && (source.isDiscovered() == isDiscoveredFilter)
                        && ((searchText == null || searchText.isEmpty())
                                || (source.getName().toLowerCase().contains(searchText.toLowerCase()) ||
                                        source.getUrl().toLowerCase().contains(searchText.toLowerCase()))));

        // Convert plugin sources to API sources
        var apiSources = pluginSources.stream()
                .map(this::mapToApiSource)
                .toList();

        return Response
                .ok(ListCsafSourcesResponse.builder()
                        .data(apiSources)
                        .build())
                .header(TOTAL_COUNT_HEADER, apiSources.size())
                .build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_CREATE)
    public Response createCsafSource(org.dependencytrack.api.v2.model.CsafSource apiSource) {
        // Convert API source to plugin source
        var pluginSource = mapToPluginSource(apiSource);

        // Validate URL (which can either be a domain or a full URL)
        if (!DOMAIN_VALIDATOR.isValid(pluginSource.getUrl(), null) &&
                !URL_VALIDATOR.isValid(pluginSource.getUrl(), null)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid domain or url").build();
        }

        // Fetch existing sources
        var sources = new ArrayList<>(getPluginCsafSourcesFromConfig(filter -> true));

        // Ensure that the new source does not already exist, by the URL
        if (sources.stream().anyMatch(s -> s.getUrl().equalsIgnoreCase(pluginSource.getUrl()))) {
            throw new AlreadyExistsException("A CSAF source with the specified URL already exists", null);
        }

        // Compute globally unique ID
        int newId = sources.stream()
                .mapToInt(CsafSource::getId)
                .max()
                .orElse(-1) + 1;

        // Set properties
        pluginSource.setId(newId);
        pluginSource.setDomain(DOMAIN_VALIDATOR.isValid(pluginSource.getUrl(), null));
        sources.add(pluginSource);

        // Update config
        updateSourcesInConfig(sources);

        return Response.status(Response.Status.CREATED).entity(mapToApiSource(pluginSource)).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE)
    public Response updateCsafSource(CsafSourceUpdateRequest apiSource) {
        // Validate URL (which can either be a domain or a full URL)
        if (!DOMAIN_VALIDATOR.isValid(apiSource.getUrl(), null) &&
                !URL_VALIDATOR.isValid(apiSource.getUrl(), null)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid domain or url").build();
        }

        // Fetch an existing source and look for the one to update
        var sources = getPluginCsafSourcesFromConfig(filter -> true);
        var existingSource = getCsafSourceByIdFromConfig(sources, apiSource.getId());
        if (existingSource == null) {
            throw new NotFoundException();
        }

        // Update the existing source with values from the update request
        existingSource.setName(apiSource.getName());
        existingSource.setEnabled(apiSource.getEnabled() != null && apiSource.getEnabled());
        existingSource.setUrl(apiSource.getUrl());
        existingSource.setAggregator(apiSource.getAggregator() != null && apiSource.getAggregator());
        existingSource.setDomain(DOMAIN_VALIDATOR.isValid(apiSource.getUrl(), null));
        
        // Update discovered - default to false if not provided
        existingSource.setDiscovered(apiSource.getDiscovered() != null && apiSource.getDiscovered());
        
        // Update lastFetched - convert from OffsetDateTime to Instant (allows null for reset)
        existingSource.setLastFetched(apiSource.getLastFetched() != null 
                ? Instant.ofEpochMilli(apiSource.getLastFetched())
                : null);

        // Update config
        updateSourcesInConfig(sources);

        return Response.ok(mapToApiSource(existingSource)).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_MANAGEMENT_DELETE)
    public Response deleteCsafSource(Integer csafSourceId) {
        // Fetch existing sources and look for the one to delete
        var sources = new ArrayList<>(getPluginCsafSourcesFromConfig(null));
        var source = getCsafSourceByIdFromConfig(sources, csafSourceId);
        if (source == null) {
            throw new NotFoundException();
        }

        // Remove the source from the list
        sources.remove(source);

        // Update config
        updateSourcesInConfig(sources);

        return Response.status(Response.Status.NO_CONTENT).build();
    }

    /**
     * Converts a Plugin {@link CsafSource} to an
     * API {@link org.dependencytrack.api.v2.model.CsafSource}.
     */
    private org.dependencytrack.api.v2.model.CsafSource mapToApiSource(
            CsafSource pluginSource) {
        return org.dependencytrack.api.v2.model.CsafSource.builder()
                .id(pluginSource.getId())
                .name(pluginSource.getName())
                .url(pluginSource.getUrl())
                .aggregator(pluginSource.isAggregator())
                .discovered(pluginSource.isDiscovered())
                .enabled(pluginSource.isEnabled())
                .domain(pluginSource.isDomain())
                .lastFetched(pluginSource.getLastFetched() != null 
                        ? pluginSource.getLastFetched().toEpochMilli()
                        : null)
                .build();
    }

    /**
     * Converts an API {@link org.dependencytrack.api.v2.model.CsafSource} to a Plugin
     * {@link CsafSource}.
     */
    private CsafSource mapToPluginSource(
            org.dependencytrack.api.v2.model.CsafSource apiSource) {
        var pluginSource = new CsafSource();
        pluginSource.setId(apiSource.getId() != null ? apiSource.getId() : 0);
        pluginSource.setName(apiSource.getName());
        pluginSource.setUrl(apiSource.getUrl());
        pluginSource.setAggregator(apiSource.getAggregator() != null && apiSource.getAggregator());
        pluginSource.setDiscovered(apiSource.getDiscovered() != null && apiSource.getDiscovered());
        pluginSource.setEnabled(apiSource.getEnabled() != null && apiSource.getEnabled());
        pluginSource.setDomain(apiSource.getDomain() != null && apiSource.getDomain());
        if (apiSource.getLastFetched() != null) {
            pluginSource.setLastFetched(Instant.ofEpochMilli(apiSource.getLastFetched()));
        }
        return pluginSource;
    }

    /**
     * Returns a list of CSAF sources (plugin model) from the configuration, filtered by the provided predicate.
     *
     * @param filter the predicate to filter the sources
     * @return a list of plugin CSAF sources
     */
    private static List<CsafSource> getPluginCsafSourcesFromConfig(
            @Nullable Predicate<CsafSource> filter) {
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
     * Returns a CSAF source by its ID from the configuration.
     *
     * @param id the ID of the CSAF source
     * @return the CSAF source, or null if not found
     */
    @javax.annotation.Nullable
    static CsafSource getCsafSourceByIdFromConfig(List<CsafSource> sources, int id) {
        // Fetch existing aggregators and look for the specific one
        return sources.stream()
                .filter(s -> s.getId() == id)
                .findFirst().orElse(null);
    }

    /**
     * Updates the CSAF sources in the configuration.
     *
     * @param sources the list of CSAF sources to set in the configuration.
     */
    static void updateSourcesInConfig(List<CsafSource> sources) {
        var config = ConfigRegistryImpl.forExtension("vuln.datasource", "csaf");
        config.setValue(
                CsafVulnDataSourceConfigs.CONFIG_SOURCES,
                SourcesManager.serializeSources(new ObjectMapper().registerModule(new JavaTimeModule()), sources)
        );
    }

}
