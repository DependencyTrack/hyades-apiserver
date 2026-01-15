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

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.ExtensionConfigDao;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSchemaSource;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.secret.TestSecretManager;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class ExtensionsResourceTest extends ResourceTest {

    private static PluginManager pluginManager;
    private static SecretManager secretManager;

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bindFactory(() -> pluginManager).to(PluginManager.class);
                            bindFactory(() -> secretManager).to(SecretManager.class);
                        }
                    }));

    @BeforeAll
    static void beforeAll() {
        secretManager = new TestSecretManager();

        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                secretManager::getSecretValue,
                List.of(DummyExtensionPoint.class));
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));
    }

    @AfterAll
    static void afterAll() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    public void listExtensionPointsShouldListAllExtensionPoints() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/extension-points")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "extension_points": [
                    {
                      "name": "dummy"
                    }
                  ]
                }
                """);
    }

    @Test
    public void listExtensionsShouldListAllExtensions() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/extension-points/dummy/extensions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "extensions":[
                    {
                      "name": "dummy.extension"
                    }
                  ]
                }
                """);
    }

    @Test
    public void listExtensionsShouldReturnNotFoundWhenExtensionPointDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/extension-points/doesNotExist/extensions")
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
    public void getExtensionConfigShouldReturnConfig() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        useJdbiTransaction(
                handle -> handle.attach(ExtensionConfigDao.class)
                        .saveConfig("dummy", "dummy.extension", /* language=JSON */ """
                                {
                                  "requiredString": "yay!"
                                }
                                """));

        final Response response = jersey.target("/extension-points/dummy/extensions/dummy.extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "config":{
                    "requiredString": "yay!"
                  }
                }
                """);
    }

    @Test
    public void getExtensionConfigShouldReturnNotFoundWhenNotExists() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/extension-points/dummy/extensions/doesNotExist/config")
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
    public void updateExtensionConfigShouldReturnNoContent() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey.target("/extension-points/dummy/extensions/dummy.extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "requiredString": "foo",
                            "optionalString": "bar"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        final String savedConfig = withJdbiHandle(
                handle -> handle.attach(ExtensionConfigDao.class).getConfig("dummy", "dummy.extension"));
        assertThatJson(savedConfig).isEqualTo(/* language=JSON */ """
                {
                  "requiredString": "foo",
                  "optionalString": "bar"
                }
                """);
    }

    @Test
    public void updateExtensionConfigShouldReturnNotModifiedWhenUnchanged() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        useJdbiTransaction(
                handle -> handle
                        .attach(ExtensionConfigDao.class)
                        .saveConfig("dummy", "dummy.extension", /* language=JSON */ """
                                {
                                  "requiredString": "foo",
                                  "optionalString": "bar"
                                }
                                """));

        final Response response = jersey.target("/extension-points/dummy/extensions/dummy.extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "requiredString": "foo",
                            "optionalString": "bar"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(304);
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    public void updateExtensionConfigShouldReturnBadRequestWhenInvalid() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey.target("/extension-points/dummy/extensions/dummy.extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "requiredString": null
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "JSON Schema Validation Failed",
                  "detail": "The provided configuration failed JSON schema validation.",
                  "errors": [
                    {
                      "evaluation_path": "$.properties.requiredString.type",
                      "schema_location": "#/properties/requiredString/type",
                      "instance_location": "$.requiredString",
                      "keyword": "type",
                      "message": "$.requiredString: null found, string expected"
                    }
                  ]
                }
                """);
    }

    @Test
    public void getExtensionConfigSchemaShouldReturnConfigSchema() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/extension-points/dummy/extensions/dummy.extension/config-schema")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "$schema": "https://json-schema.org/draft/2020-12/schema",
                  "type": "object",
                  "properties": {
                    "requiredString": {
                      "type": "string",
                      "description": "A required string"
                    },
                    "optionalString": {
                      "type": "string",
                      "description": "An optional string"
                    }
                  },
                  "additionalProperties": false,
                  "required": [
                    "requiredString"
                  ]
                }
                """);
    }

    @ExtensionPointSpec(name = "dummy", required = false)
    private interface DummyExtensionPoint extends ExtensionPoint {
    }

    private static class DummyExtension implements DummyExtensionPoint {
    }

    private record DummyRuntimeConfig(
            String requiredString,
            String optionalString) implements RuntimeConfig {
    }

    private static class DummyExtensionFactory implements ExtensionFactory<DummyExtensionPoint> {

        @Override
        public @NonNull String extensionName() {
            return "dummy.extension";
        }

        @Override
        public @NonNull Class<? extends DummyExtensionPoint> extensionClass() {
            return DummyExtension.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public RuntimeConfigSpec runtimeConfigSpec() {
            final var defaultConfig = new DummyRuntimeConfig("test", null);
            return new RuntimeConfigSpec(
                    defaultConfig,
                    new RuntimeConfigSchemaSource.Literal(/* language=JSON */ """
                            {
                              "$schema": "https://json-schema.org/draft/2020-12/schema",
                              "type": "object",
                              "properties": {
                                "requiredString": {
                                  "type": "string",
                                  "description": "A required string"
                                },
                                "optionalString": {
                                  "type": "string",
                                  "description": "An optional string"
                                }
                              },
                              "additionalProperties": false,
                              "required": [
                                "requiredString"
                              ]
                            }
                            """));
        }

        @Override
        public void init(@NonNull ExtensionContext ctx) {
        }

        @Override
        public DummyExtensionPoint create() {
            return new DummyExtension();
        }

    }

}