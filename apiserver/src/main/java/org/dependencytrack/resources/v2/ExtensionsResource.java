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

import alpine.server.auth.PermissionRequired;
import org.dependencytrack.api.v2.ExtensionsApi;
import org.dependencytrack.api.v2.model.ExtensionConfigDefinition;
import org.dependencytrack.api.v2.model.ExtensionConfigType;
import org.dependencytrack.api.v2.model.ListExtensionConfigsResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponseItem;
import org.dependencytrack.api.v2.model.ListExtensionsResponse;
import org.dependencytrack.api.v2.model.ListExtensionsResponseItem;
import org.dependencytrack.api.v2.model.UpdateExtensionConfigsRequest;
import org.dependencytrack.api.v2.model.UpdateExtensionConfigsRequestItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.plugin.ConfigRegistryImpl;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.config.ConfigType;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.util.HashMap;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @since 5.7.0
 */
@Provider
public class ExtensionsResource implements ExtensionsApi {

    @Inject
    private PluginManager pluginManager;

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listExtensionPoints() {
        final SequencedCollection<ExtensionPointSpec<?>> extensionPoints =
                pluginManager.getExtensionPoints();

        final var response = ListExtensionPointsResponse.builder()
                .extensionPoints(
                        extensionPoints.stream()
                                .map(ExtensionPointSpec::name)
                                .sorted()
                                .<ListExtensionPointsResponseItem>map(
                                        name -> ListExtensionPointsResponseItem.builder()
                                                .name(name)
                                                .build())
                                .toList())
                .build();

        return Response.ok(response).build();
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listExtensions(final String extensionPointName) {
        final ExtensionPointSpec<?> extensionPoint =
                pluginManager.getExtensionPoints().stream()
                        .filter(spec -> spec.name().equals(extensionPointName))
                        .findAny()
                        .orElseThrow(NotFoundException::new);

        final SequencedCollection<ExtensionFactory> extensionFactories =
                pluginManager.getFactories(extensionPoint.extensionPointClass());

        final var response = ListExtensionsResponse.builder()
                .extensions(
                        extensionFactories.stream()
                                .map(ExtensionFactory::extensionName)
                                .sorted()
                                .<ListExtensionsResponseItem>map(
                                        extensionName -> ListExtensionsResponseItem.builder()
                                                .name(extensionName)
                                                .build())
                                .toList())
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listExtensionConfigs(
            final String extensionPointName,
            final String extensionName) {
        final ExtensionPointSpec<?> extensionPoint =
                pluginManager.getExtensionPoints().stream()
                        .filter(spec -> spec.name().equals(extensionPointName))
                        .findAny()
                        .orElseThrow(NotFoundException::new);

        final ExtensionFactory<?> extensionFactory =
                pluginManager.getFactories(extensionPoint.extensionPointClass()).stream()
                        .filter(factory -> factory.extensionName().equals(extensionName))
                        .findAny()
                        .orElseThrow(NotFoundException::new);

        var responseItems = extensionFactory.runtimeConfigs().stream()
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

        final var response = ListExtensionConfigsResponse.builder()
                .configs(responseItems)
                .build();

        return Response.ok(response).build();
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateExtensionConfigs(
            final String extensionPointName,
            final String extensionName,
            final UpdateExtensionConfigsRequest request) {
        final ExtensionPointSpec<?> extensionPoint =
                pluginManager.getExtensionPoints().stream()
                        .filter(spec -> spec.name().equals(extensionPointName))
                        .findAny()
                        .orElseThrow(NotFoundException::new);

        final ExtensionFactory<?> extensionFactory =
                pluginManager.getFactories(extensionPoint.extensionPointClass()).stream()
                        .filter(factory -> factory.extensionName().equals(extensionName))
                        .findAny()
                        .orElseThrow(NotFoundException::new);

        final Map<String, RuntimeConfigDefinition<?>> configByName =
                extensionFactory.runtimeConfigs().stream()
                        .collect(Collectors.toMap(
                                RuntimeConfigDefinition::name,
                                Function.identity()));

        final var valueByConfig = new HashMap<RuntimeConfigDefinition, Object>(request.getConfigs().size());

        // TODO: Report all unknown configs and invalid values via problem details.
        for (final UpdateExtensionConfigsRequestItem item : request.getConfigs()) {
            final RuntimeConfigDefinition<?> config = configByName.get(item.getName());
            if (config == null) {
                throw new BadRequestException();
            }

            final Object value;
            try {
                value = config.type().fromString(item.getValue());
            } catch (RuntimeException e) {
                throw new BadRequestException();
            }

            valueByConfig.put(config, value);
        }

        // TODO: Use a bulk update mechanism to preserve atomicity.
        final var configRegistry = ConfigRegistryImpl.forExtension(
                extensionPointName, extensionName);
        for (final Map.Entry<RuntimeConfigDefinition, Object> entry : valueByConfig.entrySet()) {
            configRegistry.setValue(entry.getKey(), entry.getValue());
        }

        return Response.noContent().build();
    }

}
