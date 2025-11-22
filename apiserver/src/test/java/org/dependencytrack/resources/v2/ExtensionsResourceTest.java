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

import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.ExtensionConfigDao;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.jspecify.annotations.NonNull;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
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
    public void getExtensionConfigShouldReturnEncodedConfig() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        useJdbiTransaction(
                handle -> handle.attach(ExtensionConfigDao.class)
                        .saveConfig("foo", "bar", /* language=YAML */ """
                                ---
                                foo: bar
                                # comment
                                baz: |-
                                  123
                                  456
                                """));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/config")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);

        final JsonObject config = parseJsonObject(response);
        assertThat(config).containsOnlyKeys("config");

        assertThat(config.getString("config"))
                .asBase64Decoded()
                .asString()
                .isEqualTo(/* language=YAML */ """
                        ---
                        foo: bar
                        # comment
                        baz: |-
                          123
                          456
                        """);
    }

    @Test
    public void getExtensionConfigShouldReturnNotFoundWhenNotExists() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/extension-points/foo/extensions/bar/config")
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

    private interface DummyExtensionPoint extends ExtensionPoint {
    }

    private static class DummyExtensionPointSpec implements ExtensionPointSpec<@NonNull DummyExtensionPoint> {

        private final String name;

        private DummyExtensionPointSpec(final String name) {
            this.name = name;
        }

        @Override
        public @NonNull String name() {
            return name;
        }

        @Override
        public boolean required() {
            return false;
        }

        @Override
        public @NonNull Class<DummyExtensionPoint> extensionPointClass() {
            return DummyExtensionPoint.class;
        }

    }

    private static class DummyExtension implements DummyExtensionPoint {
    }

    private static class DummyExtensionFactory implements ExtensionFactory<DummyExtensionPoint> {

        private final String name;

        private DummyExtensionFactory(final String name) {
            this.name = name;
        }

        @Override
        public @NonNull String extensionName() {
            return name;
        }

        @Override
        public @NonNull Class<? extends DummyExtensionPoint> extensionClass() {
            return DummyExtensionPoint.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public Class<? extends RuntimeConfig> runtimeConfigClass() {
            return null;
        }

        @Override
        public RuntimeConfig defaultRuntimeConfig() {
            return null;
        }

        @Override
        public void init(final @NonNull ExtensionContext ctx) {
        }

        @Override
        public DummyExtensionPoint create() {
            return new DummyExtension();
        }

    }

}