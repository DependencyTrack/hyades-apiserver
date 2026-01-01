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
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.secret.management.SecretAlreadyExistsException;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SecretsResourceTest extends ResourceTest {

    private static final SecretManager SECRET_MANAGER_MOCK = mock(SecretManager.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(SECRET_MANAGER_MOCK).to(SecretManager.class);
                        }
                    }));

    @AfterEach
    @Override
    public void after() {
        Mockito.reset(SECRET_MANAGER_MOCK);
        super.after();
    }

    @Test
    public void createSecretShouldCreateSecretAndReturnNoContent() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_CREATE);

        final Response response = jersey
                .target("/secrets")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "foo",
                          "description": "bar",
                          "value": "baz"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        verify(SECRET_MANAGER_MOCK).createSecret(eq("foo"), eq("bar"), eq("baz"));
    }

    @Test
    public void createSecretShouldReturnBadRequestWhenSecretManagerIsReadOnly() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_CREATE);

        doThrow(new UnsupportedOperationException("Not supported"))
                .when(SECRET_MANAGER_MOCK).createSecret(eq("foo"), any(), any());

        final Response response = jersey
                .target("/secrets")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "foo",
                          "description": "new-bar",
                          "value": "new-baz"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Not supported"
                }
                """);
    }

    @Test
    public void createSecretShouldReturnConflictWhenAlreadyExists() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_CREATE);

        doThrow(new SecretAlreadyExistsException("foo"))
                .when(SECRET_MANAGER_MOCK).createSecret(anyString(), any(), any());

        final Response response = jersey
                .target("/secrets")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "foo",
                          "description": "new-bar",
                          "value": "new-baz"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 409,
                  "title": "Resource already exists",
                  "detail": "A secret with name foo already exists"
                }
                """);
    }

    @Test
    public void updateSecretShouldUpdateDescriptionAndReturnNoContent() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_UPDATE);

        doReturn(true).when(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), any(), any());

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "description": "new-description"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        verify(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), eq("new-description"), isNull());
    }

    @Test
    public void updateSecretShouldUpdateValueAndReturnNoContent() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_UPDATE);

        doReturn(true).when(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), any(), any());

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "value": "new-value"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        verify(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), isNull(), eq("new-value"));
    }

    @Test
    public void updateSecretShouldReturnNotModifiedWhenUnchanged() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_UPDATE);

        doReturn(false).when(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), any(), any());

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {}
                        """));
        assertThat(response.getStatus()).isEqualTo(304);
        assertThat(getPlainTextBody(response)).isEmpty();

        verify(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), isNull(), isNull());
    }

    @Test
    public void updateSecretShouldReturnBadRequestWhenSecretManagerIsReadOnly() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_UPDATE);

        doThrow(new UnsupportedOperationException("Not supported"))
                .when(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), any(), any());

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "description": "new-description"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Not supported"
                }
                """);
    }

    @Test
    public void updateSecretShouldReturnNotFoundWhenSecretDoesNotExist() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_UPDATE);

        doThrow(new NoSuchElementException("No secret with name foo found"))
                .when(SECRET_MANAGER_MOCK).updateSecret(eq("foo"), any(), any());

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "value": "new-value"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "No secret with name foo found"
                }
                """);
    }

    @Test
    public void deleteSecretShouldDeleteSecretAndReturnNoContent() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_DELETE);

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        verify(SECRET_MANAGER_MOCK).deleteSecret(eq("foo"));
    }

    @Test
    public void deleteSecretShouldReturnBadRequestWhenSecretManagerIsReadOnly() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_DELETE);

        doThrow(new UnsupportedOperationException("Not supported"))
                .when(SECRET_MANAGER_MOCK).deleteSecret(eq("foo"));

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Not supported"
                }
                """);
    }

    @Test
    public void deleteSecretShouldReturnNotFoundWhenSecretDoesNotExist() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_DELETE);

        doThrow(new NoSuchElementException("No secret with name foo found"))
                .when(SECRET_MANAGER_MOCK).deleteSecret(eq("foo"));

        final Response response = jersey
                .target("/secrets/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "No secret with name foo found"
                }
                """);
    }

    @Test
    public void listSecretsShouldReturnEmptyArrayWhenNoSecretsExist() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_READ);

        doReturn(Collections.emptyList()).when(SECRET_MANAGER_MOCK).listSecrets();

        final Response response = jersey
                .target("/secrets")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "secrets": []
                }
                """);
    }

    @Test
    public void listSecretsShouldReturnSecrets() {
        initializeWithPermissions(Permissions.SECRET_MANAGEMENT_READ);

        doReturn(List.of(
                new SecretMetadata("foo", "foo-description", Instant.now(), null),
                new SecretMetadata("bar", "bar-description", Instant.now(), Instant.now()),
                new SecretMetadata("baz", "baz-description", Instant.now(), null)))
                .when(SECRET_MANAGER_MOCK).listSecrets();

        final Response response = jersey
                .target("/secrets")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "secrets": [
                            {
                              "name": "bar",
                              "description": "bar-description",
                              "created_at": "${json-unit.any-number}",
                              "updated_at": "${json-unit.any-number}"
                            },
                            {
                              "name": "baz",
                              "description": "baz-description",
                              "created_at": "${json-unit.any-number}"
                            },
                            {
                              "name": "foo",
                              "description": "foo-description",
                              "created_at": "${json-unit.any-number}"
                            }
                          ]
                        }
                        """);
    }

}