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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.datasource.vuln.csaf.CsafSource;
import org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceFactory;
import org.dependencytrack.plugin.ConfigRegistryImpl;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.PluginManagerBinder;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceSpec;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.List;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

public class CsafResourceTest extends ResourceTest {

    private static final PluginManager PLUGIN_MANAGER_MOCK = mock(PluginManager.class);

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(CsafResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(PluginManagerBinder.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(PLUGIN_MANAGER_MOCK).to(PluginManager.class);
                        }
                    }));

    @After
    public void after() {
        reset(PLUGIN_MANAGER_MOCK);
        super.after();
    }

    @Before
    @Override
    public void before() throws Exception {
        super.before();
    }

    @Test
    public void createCsafSourceTest() {
        final ExtensionPointSpec<VulnDataSource> extensionPointSpec = new VulnDataSourceSpec();
        final ExtensionFactory<VulnDataSource> extensionFactory = new CsafVulnDataSourceFactory();
        final var configRegistry = ConfigRegistryImpl.forExtension(extensionPointSpec.name(), extensionFactory.extensionName());
        configRegistry.createWithDefaultsIfNotExist(extensionFactory.runtimeConfigs());

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();
        doReturn(List.of(extensionFactory)).when(PLUGIN_MANAGER_MOCK).getFactories(eq(VulnDataSource.class));

        CsafSource aggregator = new CsafSource();
        aggregator.setName("Testsource");
        aggregator.setUrl("example.com");
        aggregator.setEnabled(true);

        Response response = jersey.target(V1_CSAF).path("/aggregators/").request().header(X_API_KEY, apiKey)
                .put(Entity.entity(aggregator, MediaType.APPLICATION_JSON));
        Assert.assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus());

        response = jersey.target(V1_CSAF).path("/aggregators/").request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus(), 0);

        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
    }

    @Test
    public void updateCsafSourceTest() {
        final ExtensionPointSpec<VulnDataSource> extensionPointSpec = new VulnDataSourceSpec();
        final ExtensionFactory<VulnDataSource> extensionFactory = new CsafVulnDataSourceFactory();
        final var configRegistry = ConfigRegistryImpl.forExtension(extensionPointSpec.name(), extensionFactory.extensionName());
        configRegistry.createWithDefaultsIfNotExist(extensionFactory.runtimeConfigs());

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();
        doReturn(List.of(extensionFactory)).when(PLUGIN_MANAGER_MOCK).getFactories(eq(VulnDataSource.class));

        CsafSource aggregator = new CsafSource();
        aggregator.setId(0);
        aggregator.setName("Testsource");
        aggregator.setUrl("example.com");
        aggregator.setEnabled(true);

        Response response = jersey.target(V1_CSAF).path("/aggregators/").request().header(X_API_KEY, apiKey)
                .post(Entity.entity(aggregator, MediaType.APPLICATION_JSON));
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertTrue(json.getBoolean("domain"));
    }

}
