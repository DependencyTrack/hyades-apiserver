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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.ExtensionsApi;
import org.dependencytrack.api.v2.model.GetExtensionConfigResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponseItem;
import org.dependencytrack.api.v2.model.ListExtensionsResponse;
import org.dependencytrack.api.v2.model.ListExtensionsResponseItem;
import org.dependencytrack.api.v2.model.UpdateExtensionConfigRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.ExtensionConfigDao;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.runtime.config.RuntimeConfigMapper;
import org.dependencytrack.resources.AbstractApiResource;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.SequencedCollection;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@Path("/")
public class ExtensionsResource extends AbstractApiResource implements ExtensionsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExtensionsResource.class);

    @Inject
    private PluginManager pluginManager;

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listExtensionPoints() {
        final SequencedCollection<ExtensionPointSpec> extensionPoints =
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
    public Response listExtensions(String extensionPointName) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);

        final SequencedCollection<ExtensionFactory> extensionFactories =
                pluginManager.getFactories(extensionPointClass);

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
    @SuppressWarnings("rawtypes")
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getExtensionConfig(
            String extensionPointName,
            String extensionName) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);
        final ExtensionFactory extensionFactory =
                getExtensionFactory(extensionPointClass, extensionName);

        if (extensionFactory.runtimeConfigSpec() == null) {
            throw new NotFoundException();
        }

        final String configJson = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(ExtensionConfigDao.class).getConfig(
                        extensionPointName, extensionName));
        if (configJson == null) {
            throw new NotFoundException();
        }

        final ObjectMapper jsonMapper = RuntimeConfigMapper.getInstance().getJsonMapper();
        final Map<String, Object> parsedConfigJson;
        try {
            parsedConfigJson = jsonMapper.readValue(configJson, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final var response = GetExtensionConfigResponse.builder()
                .config(parsedConfigJson)
                .build();

        return Response.ok(response).build();
    }

    @Override
    @SuppressWarnings("rawtypes")
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateExtensionConfig(
            String extensionPointName,
            String extensionName,
            UpdateExtensionConfigRequest request) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);
        final ExtensionFactory extensionFactory =
                getExtensionFactory(extensionPointClass, extensionName);

        final RuntimeConfigSpec runtimeConfigSpec = extensionFactory.runtimeConfigSpec();
        if (runtimeConfigSpec == null) {
            throw new BadRequestException();
        }

        // Unfortunately we can't receive the config object as raw string,
        // so we have to serialize it first.
        final String configJson = Json.createObjectBuilder(request.getConfig()).build().toString();

        RuntimeConfigMapper.getInstance().validateJson(configJson, runtimeConfigSpec);

        final boolean updated = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(ExtensionConfigDao.class).saveConfig(
                        extensionPointName, extensionName, configJson));
        if (!updated) {
            return Response.notModified().build();
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Updated config of extension {}/{}",
                extensionPointName,
                extensionName);

        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getExtensionConfigSchema(
            String extensionPointName,
            String extensionName) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);
        final ExtensionFactory<?> extensionFactory =
                getExtensionFactory(extensionPointClass, extensionName);

        final RuntimeConfigSpec runtimeConfigSpec = extensionFactory.runtimeConfigSpec();
        if (runtimeConfigSpec == null) {
            throw new NotFoundException();
        }

        return Response.ok(runtimeConfigSpec.schema()).build();
    }

    private Class<? extends ExtensionPoint> getExtensionPointClass(String extensionPointName) {
        return pluginManager.getExtensionPoints().stream()
                .filter(spec -> spec.name().equals(extensionPointName))
                .map(ExtensionPointSpec::extensionPointClass)
                .findAny()
                .orElseThrow(NotFoundException::new);
    }

    private ExtensionFactory<?> getExtensionFactory(
            Class<? extends ExtensionPoint> extensionPointClass,
            String extensionName) {
        return pluginManager.getFactories(extensionPointClass).stream()
                .filter(factory -> factory.extensionName().equals(extensionName))
                .findAny()
                .orElseThrow(NotFoundException::new);
    }

}
