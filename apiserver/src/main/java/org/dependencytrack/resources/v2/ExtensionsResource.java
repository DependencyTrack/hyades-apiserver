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

import org.dependencytrack.api.v2.ExtensionsApi;
import org.dependencytrack.api.v2.model.ExtensionConfigDefinition;
import org.dependencytrack.api.v2.model.ExtensionConfigType;
import org.dependencytrack.api.v2.model.ListExtensionConfigsResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponseItem;
import org.dependencytrack.api.v2.model.ListExtensionsResponse;
import org.dependencytrack.api.v2.model.ListExtensionsResponseItem;
import org.dependencytrack.api.v2.model.PaginationLinks;
import org.dependencytrack.api.v2.model.PaginationMetadata;
import org.dependencytrack.api.v2.model.UpdateExtensionConfigRequest;
import org.dependencytrack.persistence.pagination.PageUtil;
import org.dependencytrack.plugin.ConfigRegistryImpl;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.config.ConfigType;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import java.util.List;
import java.util.Optional;
import java.util.SequencedCollection;

@Provider
public class ExtensionsResource implements ExtensionsApi {

    @Context
    private UriInfo uriInfo;

    @Inject
    private PluginManager pluginManager;

    @Override
    public Response listExtensionPoints(final Integer limit, final String pageToken) {
        final List<ExtensionPointSpec<?>> extensionPoints = pluginManager.getExtensionPoints();

        final String lastName = PageUtil.decodePageToken(pageToken);

        var responseItems = extensionPoints.stream()
                .map(ExtensionPointSpec::name)
                .sorted()
                .filter(name -> lastName == null || name.compareTo(lastName) > 0)
                .<ListExtensionPointsResponseItem>map(
                        name -> ListExtensionPointsResponseItem.builder()
                                .name(name)
                                .build())
                .toList();

        final String nextPageToken = responseItems.size() > limit
                ? responseItems.getLast().getName()
                : null;
        responseItems = responseItems.subList(0, Math.min(responseItems.size(), limit));

        final var response = ListExtensionPointsResponse.builder()
                .extensionPoints(responseItems)
                .pagination(
                        PaginationMetadata.builder()
                                .links(PaginationLinks.builder()
                                        .self(uriInfo.getRequestUri())
                                        .next(nextPageToken != null
                                                ? uriInfo.getRequestUriBuilder()
                                                .replaceQueryParam("page_token", nextPageToken)
                                                .build()
                                                : null)
                                        .build())
                                .build())
                .build();

        return Response.ok(response).build();
    }

    @Override
    public Response listExtensions(
            final String extensionPointName,
            final Integer limit,
            final String pageToken) {
        final SequencedCollection<ExtensionFactory<?>> extensionFactories =
                pluginManager.getFactories(extensionPointName);

        String lastName = PageUtil.decodePageToken(pageToken);

        var responseItems = extensionFactories.stream()
                .map(ExtensionFactory::extensionName)
                .sorted()
                .filter(name -> lastName == null || name.compareTo(lastName) > 0)
                .<ListExtensionsResponseItem>map(
                        extensionName -> ListExtensionsResponseItem.builder()
                                .name(extensionName)
                                .build())
                .toList();

        final String nextPageToken = responseItems.size() > limit
                ? responseItems.getLast().getName()
                : null;
        responseItems = responseItems.subList(0, Math.min(responseItems.size(), limit));

        final var response = ListExtensionsResponse.builder()
                .extensions(responseItems)
                .pagination(
                        PaginationMetadata.builder()
                                .links(PaginationLinks.builder()
                                        .self(uriInfo.getRequestUri())
                                        .next(nextPageToken != null
                                                ? uriInfo.getRequestUriBuilder()
                                                .replaceQueryParam("page_token", nextPageToken)
                                                .build()
                                                : null)
                                        .build())
                                .build())
                .build();

        return Response.ok(response).build();
    }

    @Override
    public Response listExtensionConfigs(
            final String extensionPointName,
            final String extensionName,
            final Integer limit,
            final String pageToken) {
        final SequencedCollection<ExtensionFactory<?>> extensionFactories =
                pluginManager.getFactories(extensionPointName);

        final String lastName = PageUtil.decodePageToken(pageToken);

        var responseItems = extensionFactories.stream()
                .filter(factory -> factory.extensionName().equals(extensionName))
                .flatMap(factory -> factory.runtimeConfigs().stream())
                .filter(configDef -> lastName == null || configDef.name().compareTo(lastName) > 0)
                .<ExtensionConfigDefinition>map(
                        configDef -> ExtensionConfigDefinition.builder()
                                .name(configDef.name())
                                .description(configDef.description())
                                .type(switch (configDef.type()) {
                                    case ConfigType.Boolean ignored -> ExtensionConfigType.BOOLEAN;
                                    case ConfigType.Duration ignored -> ExtensionConfigType.DURATION;
                                    case ConfigType.Instant ignored -> ExtensionConfigType.INSTANT;
                                    case ConfigType.Integer ignored -> ExtensionConfigType.INTEGER;
                                    case ConfigType.Path ignored -> ExtensionConfigType.PATH;
                                    case ConfigType.String ignored -> ExtensionConfigType.STRING;
                                })
                                .isRequired(configDef.isRequired())
                                .isSecret(configDef.isSecret())
                                .build())
                .toList();

        final String nextPageToken = responseItems.size() > limit
                ? responseItems.getLast().getName()
                : null;
        responseItems = responseItems.subList(0, Math.min(responseItems.size(), limit));

        final var response = ListExtensionConfigsResponse.builder()
                .configs(responseItems)
                .pagination(
                        PaginationMetadata.builder()
                                .links(PaginationLinks.builder()
                                        .self(uriInfo.getRequestUri())
                                        .next(nextPageToken != null
                                                ? uriInfo.getRequestUriBuilder()
                                                .replaceQueryParam("page_token", nextPageToken)
                                                .build()
                                                : null)
                                        .build())
                                .build())
                .build();

        return Response.ok(response).build();
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    public Response updateExtensionConfig(
            final String extensionPointName,
            final String extensionName,
            final String configName,
            final UpdateExtensionConfigRequest request) {
        final SequencedCollection<ExtensionFactory<?>> extensionFactories =
                pluginManager.getFactories(extensionPointName);

        final ExtensionFactory<?> extensionFactory = extensionFactories.stream()
                .filter(factory -> factory.extensionName().equals(extensionName))
                .findAny()
                .orElse(null);
        if (extensionFactory == null) {
            throw new NotFoundException();
        }

        final Optional<RuntimeConfigDefinition<?>> configDefOptional =
                extensionFactory.runtimeConfigs().stream()
                        .filter(config -> config.name().equals(configName))
                        .findAny();
        if (configDefOptional.isEmpty()) {
            throw new NotFoundException();
        }

        final var configRegistry = ConfigRegistryImpl.forExtension(extensionPointName, extensionName);
        final RuntimeConfigDefinition configDef = configDefOptional.get();

        final Object configValue;
        try {
            configValue = configDef.type().fromString(request.getValue());
        } catch (RuntimeException e) {
            throw new BadRequestException("Invalid value");
        }

        configRegistry.setValue(configDef, configValue);

        return Response.ok().build();
    }
}
