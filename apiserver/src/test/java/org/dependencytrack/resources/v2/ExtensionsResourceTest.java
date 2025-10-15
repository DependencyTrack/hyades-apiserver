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

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.plugin.ConfigRegistryImpl;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static net.javacrumbs.jsonunit.core.Option.IGNORING_ARRAY_ORDER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

public class ExtensionsResourceTest extends ResourceTest {

    private static final PluginManager PLUGIN_MANAGER_MOCK = mock(PluginManager.class);

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig()
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

    @Test
    public void listExtensionPointsShouldListAllExtensionPoints() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var extensionPointSpec = new DummyExtensionPointSpec("foo");

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();

        final Response response = jersey.target("/extension-points")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "extension_points": [
                    {
                      "name": "foo"
                    }
                  ]
                }
                """);
    }

    @Test
    public void listExtensionsShouldListAllExtensions() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var extensionPointSpec = new DummyExtensionPointSpec("foo");
        final var extensionFactory = new DummyExtensionFactory("bar");

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();
        doReturn(List.of(extensionFactory)).when(PLUGIN_MANAGER_MOCK).getFactories(eq(DummyExtensionPoint.class));

        final Response response = jersey.target("/extension-points/foo/extensions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "extensions":[
                    {
                      "name": "bar"
                    }
                  ]
                }
                """);
    }

    @Test
    public void listExtensionsShouldReturnNotFoundWhenExtensionPointDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        doReturn(Collections.emptyList()).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();

        final Response response = jersey.target("/extension-points/foo/extensions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "type": "about:blank",
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void listExtensionConfigsShouldListAllExtensionConfigs() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var extensionPointSpec = new DummyExtensionPointSpec("foo");
        final var extensionFactory = new DummyExtensionFactory("bar", List.of(
                new RuntimeConfigDefinition<>("enabled", "", ConfigTypes.BOOLEAN, true, true, false),
                new RuntimeConfigDefinition<>("access.token", "", ConfigTypes.STRING, "secretValue", true, true),
                new RuntimeConfigDefinition<>("ecosystems", "", ConfigTypes.stringList(Set.of("eco1", "eco2")), List.of("eco1"), false, false)));
        final var configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        configRegistry.createWithDefaultsIfNotExist(extensionFactory.runtimeConfigs());

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();
        doReturn(List.of(extensionFactory)).when(PLUGIN_MANAGER_MOCK).getFactories(eq(DummyExtensionPoint.class));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .when(IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                {
                  "configs": [
                    {
                      "name": "enabled",
                      "description": "",
                      "type": "BOOLEAN",
                      "is_required": true,
                      "is_secret": false,
                      "value": "true"
                    },
                    {
                      "name": "access.token",
                      "description": "",
                      "type": "STRING",
                      "is_required": true,
                      "is_secret": true,
                      "value": "***SECRET-PLACEHOLDER***"
                    },
                    {
                      "description": "",
                      "is_required": false,
                      "is_secret": false,
                      "name": "ecosystems",
                      "type": "STRING_LIST",
                      "value": "eco1",
                      "allowed_values": ["eco1", "eco2"]
                    }
                  ]
                }
                """);
    }

    @Test
    public void listExtensionConfigsShouldReturnNotFoundWhenExtensionPointDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        doReturn(Collections.emptyList()).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "type": "about:blank",
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void listExtensionConfigsShouldReturnNotFoundWhenExtensionDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var extensionPointSpec = new DummyExtensionPointSpec("foo");

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "type": "about:blank",
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void updateExtensionConfigsShouldUpdateExtensionConfigValues() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final var extensionPointSpec = new DummyExtensionPointSpec("foo");
        final var extensionFactory = new DummyExtensionFactory("bar", List.of(
                new RuntimeConfigDefinition<>("enabled", "", ConfigTypes.BOOLEAN, null, true, false),
                new RuntimeConfigDefinition<>("access.token", "", ConfigTypes.STRING, null, true, true)));
        final var configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        configRegistry.createWithDefaultsIfNotExist(extensionFactory.runtimeConfigs());

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();
        doReturn(List.of(extensionFactory)).when(PLUGIN_MANAGER_MOCK).getFactories(eq(DummyExtensionPoint.class));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "configs": [
                            {
                              "name": "enabled",
                              "value": "false"
                            },
                            {
                              "name": "access.token",
                              "value": "foobarbaz"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);

        useJdbiHandle(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);
            assertThat(dao.getOptional("foo", "extension.bar.enabled"))
                    .hasValueSatisfying(configProperty -> assertThat(
                            configProperty.getPropertyValue()).isEqualTo("false"));
            assertThat(dao.getOptional("foo", "extension.bar.access.token"))
                    .hasValueSatisfying(configProperty -> assertThat(
                            configProperty.getPropertyValue()).isNotNull().isNotEqualTo("foobarbaz"));
        });
    }

    @Test
    public void updateExtensionConfigsShouldReturnBadRequestForUnknownOrInvalidOrNotProvidedConfigs() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final var extensionPointSpec = new DummyExtensionPointSpec("foo");
        final var extensionFactory = new DummyExtensionFactory("bar", List.of(
                new RuntimeConfigDefinition<>("enabled", "", ConfigTypes.BOOLEAN, null, true, false),
                new RuntimeConfigDefinition<>("some.number", "", ConfigTypes.INTEGER, null, false, false)));
        final var configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        configRegistry.createWithDefaultsIfNotExist(extensionFactory.runtimeConfigs());

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();
        doReturn(List.of(extensionFactory)).when(PLUGIN_MANAGER_MOCK).getFactories(eq(DummyExtensionPoint.class));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "configs": [
                            {
                              "name": "does.not.exist",
                              "value": "foo"
                            },
                            {
                              "name": "some.number",
                              "value": "foobarbaz"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "type": "about:blank",
                  "title": "Invalid Extension Configs",
                  "detail": "The provided extensions configs are invalid.",
                  "invalid_configs": [
                    {
                      "name": "does.not.exist",
                      "message": "Not a known extension config"
                    },
                    {
                      "name": "some.number",
                      "value": "foobarbaz",
                      "message": "Unable to convert to expected type"
                    },
                    {
                      "name": "enabled",
                      "message": "Not provided"
                    }
                  ]
                }
                """);
    }

    @Test
    public void updateExtensionConfigsShouldReturnNotFoundWhenExtensionPointDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        doReturn(Collections.emptyList()).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "configs": [
                            {
                              "name": "enabled",
                              "value": "false"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "type": "about:blank",
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void updateExtensionConfigsShouldReturnNotFoundWhenExtensionDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final var extensionPointSpec = new DummyExtensionPointSpec("foo");

        doReturn(List.of(extensionPointSpec)).when(PLUGIN_MANAGER_MOCK).getExtensionPoints();

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "configs": [
                            {
                              "name": "enabled",
                              "value": "false"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "type": "about:blank",
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    private interface DummyExtensionPoint extends ExtensionPoint {
    }

    private static class DummyExtensionPointSpec implements ExtensionPointSpec<DummyExtensionPoint> {

        private final String name;

        private DummyExtensionPointSpec(final String name) {
            this.name = name;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public boolean required() {
            return false;
        }

        @Override
        public Class<DummyExtensionPoint> extensionPointClass() {
            return DummyExtensionPoint.class;
        }

    }

    private static class DummyExtension implements DummyExtensionPoint {
    }

    private static class DummyExtensionFactory implements ExtensionFactory<DummyExtensionPoint> {

        private final String name;
        private final List<RuntimeConfigDefinition<?>> configs;

        private DummyExtensionFactory(final String name) {
            this(name, Collections.emptyList());
        }

        private DummyExtensionFactory(
                final String name,
                final List<RuntimeConfigDefinition<?>> configs) {
            this.name = name;
            this.configs = configs;
        }

        @Override
        public String extensionName() {
            return name;
        }

        @Override
        public Class<? extends DummyExtensionPoint> extensionClass() {
            return DummyExtensionPoint.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public List<RuntimeConfigDefinition<?>> runtimeConfigs() {
            return configs;
        }

        @Override
        public void init(final ExtensionContext ctx) {
        }

        @Override
        public DummyExtensionPoint create() {
            return new DummyExtension();
        }

    }

}