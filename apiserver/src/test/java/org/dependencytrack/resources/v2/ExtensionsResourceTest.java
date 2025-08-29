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

import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.plugin.ConfigRegistryImpl;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

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

    @Test
    public void listExtensionPointsShouldListAllExtensionPoints() {
        final var extensionPointSpec = new ExtensionPointSpec<>() {
            @Override
            public String name() {
                return "foo";
            }

            @Override
            public boolean required() {
                return false;
            }

            @Override
            public Class extensionPointClass() {
                return null;
            }
        };

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
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}"
                    }
                  }
                }
                """);
    }

    @Test
    public void listExtensionsShouldListAllExtensions() {
        final var extensionFactories = List.of(new ExtensionFactory<>() {

            @Override
            public String extensionName() {
                return "bar";
            }

            @Override
            public Class extensionClass() {
                return null;
            }

            @Override
            public int priority() {
                return 0;
            }

            @Override
            public void init(final ConfigRegistry configRegistry) {
            }

            @Override
            public ExtensionPoint create() {
                return null;
            }
        });

        doReturn(extensionFactories).when(PLUGIN_MANAGER_MOCK).getFactories(eq("foo"));

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
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}"
                    }
                  }
                }
                """);
    }

    @Test
    public void listExtensionConfigsShouldListAllExtensionConfigs() {
        final var extensionFactories = List.of(new ExtensionFactory<>() {
            @Override
            public String extensionName() {
                return "bar";
            }

            @Override
            public Class<? extends ExtensionPoint> extensionClass() {
                return null;
            }

            @Override
            public int priority() {
                return 0;
            }

            @Override
            public List<RuntimeConfigDefinition<?>> runtimeConfigs() {
                return List.of(
                        new RuntimeConfigDefinition<>("enabled", "", ConfigTypes.BOOLEAN, true, false),
                        new RuntimeConfigDefinition<>("access.token", "", ConfigTypes.STRING, true, true));
            }

            @Override
            public void init(final ConfigRegistry configRegistry) {

            }

            @Override
            public ExtensionPoint create() {
                return null;
            }
        });

        doReturn(extensionFactories).when(PLUGIN_MANAGER_MOCK).getFactories(eq("foo"));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "configs":[
                    {
                      "name": "enabled",
                      "description": "",
                      "type": "BOOLEAN",
                      "is_required": true,
                      "is_secret": false
                    },
                    {
                      "name": "access.token",
                      "description": "",
                      "type": "STRING",
                      "is_required": true,
                      "is_secret": true
                    }
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}"
                    }
                  }
                }
                """);
    }

    @Test
    public void updateExtensionConfigShouldUpdateConfigValue() {
        final var configDef = new RuntimeConfigDefinition<>("baz", "", ConfigTypes.STRING, true, false);

        final var extensionFactories = List.of(new ExtensionFactory<>() {
            @Override
            public String extensionName() {
                return "bar";
            }

            @Override
            public Class<? extends ExtensionPoint> extensionClass() {
                return null;
            }

            @Override
            public int priority() {
                return 0;
            }

            @Override
            public List<RuntimeConfigDefinition<?>> runtimeConfigs() {
                return List.of(configDef);
            }

            @Override
            public void init(final ConfigRegistry configRegistry) {
            }

            @Override
            public ExtensionPoint create() {
                return null;
            }
        });

        doReturn(extensionFactories).when(PLUGIN_MANAGER_MOCK).getFactories(eq("foo"));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs/baz")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "value": "newValue"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);

        final var configRegistry = ConfigRegistryImpl.forExtension("foo", "bar");
        assertThat(configRegistry.getOptionalValue(configDef)).contains("newValue");
    }

    @Test
    public void updateExtensionConfigShouldReturnNotFoundWhenExtensionDoesNotExist() {
        doReturn(Collections.emptyList()).when(PLUGIN_MANAGER_MOCK).getFactories(eq("foo"));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs/baz")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "value": "newValue"
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
    public void updateExtensionConfigShouldReturnNotFoundWhenExtensionConfigDoesNotExist() {
        final var extensionFactories = List.of(new ExtensionFactory<>() {
            @Override
            public String extensionName() {
                return "bar";
            }

            @Override
            public Class<? extends ExtensionPoint> extensionClass() {
                return null;
            }

            @Override
            public int priority() {
                return 0;
            }

            @Override
            public List<RuntimeConfigDefinition<?>> runtimeConfigs() {
                return Collections.emptyList();
            }

            @Override
            public void init(final ConfigRegistry configRegistry) {
            }

            @Override
            public ExtensionPoint create() {
                return null;
            }
        });

        doReturn(extensionFactories).when(PLUGIN_MANAGER_MOCK).getFactories(eq("foo"));

        final Response response = jersey.target("/extension-points/foo/extensions/bar/configs/baz")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "value": "newValue"
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

}