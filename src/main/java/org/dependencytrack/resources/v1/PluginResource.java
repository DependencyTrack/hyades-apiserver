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

import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.Provider;
import org.dependencytrack.plugin.ProviderFactory;
import org.dependencytrack.resources.v1.vo.LoadedPluginListResponseItem;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.SortedSet;

@Path("/v1/plugin")
@Api(value = "plugin", authorizations = @Authorization(value = "X-Api-Key"))
public class PluginResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all loaded plugins",
            response = LoadedPluginListResponseItem.class,
            responseContainer = "List",
            notes = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getAllLoadedPlugins() {
        final var providerManager = PluginManager.getInstance();

        final List<LoadedPluginListResponseItem> loadedPlugins = providerManager.getLoadedPlugins().stream()
                .map(plugin -> {
                    final SortedSet<? extends ProviderFactory<? extends Provider>> factories =
                            providerManager.getFactories(plugin.providerClass());
                    final List<String> providerNames = factories.stream()
                            .map(ProviderFactory::providerName)
                            .toList();

                    final ProviderFactory<?> defaultFactory = providerManager.getFactory(plugin.providerClass());
                    final String defaultProviderName = defaultFactory != null ? defaultFactory.providerName() : null;

                    return new LoadedPluginListResponseItem(plugin.name(), providerNames, defaultProviderName);
                })
                .toList();

        return Response.ok(loadedPlugins).build();
    }

}
