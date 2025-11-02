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
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.CacheControl;
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
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.config.mapping.RuntimeConfigMapper;
import org.dependencytrack.resources.AbstractApiResource;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.SequencedCollection;
import java.util.concurrent.TimeUnit;

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
        final Class<? extends ExtensionPoint> extensionPointClass = getExtensionPointClass(extensionPointName);

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
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getExtensionConfig(
            final String extensionPointName,
            final String extensionName) {
        final String configJson = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(ExtensionConfigDao.class).getConfig(
                        extensionPointName, extensionName));
        if (configJson == null) {
            throw new NotFoundException();
        }

        final String encodedConfigJson =
                Base64.getEncoder().encodeToString(configJson.getBytes());

        return Response.ok(
                        GetExtensionConfigResponse.builder()
                                .config(encodedConfigJson)
                                .build())
                .build();
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateExtensionConfig(
            final String extensionPointName,
            final String extensionName,
            final UpdateExtensionConfigRequest request) {
        final Class<? extends ExtensionPoint> extensionPointClass = getExtensionPointClass(extensionPointName);
        final ExtensionFactory extensionFactory = getExtensionFactory(extensionPointClass, extensionName);

        final Class<? extends RuntimeConfig> configClass = extensionFactory.runtimeConfigClass();
        if (configClass == null) {
            throw new BadRequestException();
        }

        final String configJson = new String(Base64.getDecoder().decode(request.getConfig()));
        RuntimeConfigMapper.getInstance().validateYaml(configJson, configClass);

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
            final String extensionPointName,
            final String extensionName) {
        final Class<? extends ExtensionPoint> extensionPointClass = getExtensionPointClass(extensionPointName);
        final ExtensionFactory<?> extensionFactory = getExtensionFactory(extensionPointClass, extensionName);

        final var cacheControl = new CacheControl();
        cacheControl.setMaxAge((int) TimeUnit.MINUTES.toSeconds(5));

        final Class<? extends RuntimeConfig> configClass = extensionFactory.runtimeConfigClass();
        if (configClass == null) {
            return Response
                    .noContent()
                    .cacheControl(cacheControl)
                    .build();
        }

        final String jsonSchema = RuntimeConfigMapper.getInstance().getJsonSchema(configClass);

        return Response
                .ok(jsonSchema)
                .cacheControl(cacheControl)
                .build();
    }

    private Class<? extends ExtensionPoint> getExtensionPointClass(final String extensionPointName) {
        return pluginManager.getExtensionPoints().stream()
                .filter(spec -> spec.name().equals(extensionPointName))
                .map(ExtensionPointSpec::extensionPointClass)
                .findAny()
                .orElseThrow(NotFoundException::new);
    }

    private ExtensionFactory<?> getExtensionFactory(
            final Class<? extends ExtensionPoint> extensionPointClass,
            final String extensionName) {
        return pluginManager.getFactories(extensionPointClass).stream()
                .filter(factory -> factory.extensionName().equals(extensionName))
                .findAny()
                .orElseThrow(NotFoundException::new);
    }

}
