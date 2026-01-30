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
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.csaf.CsafAggregator;
import org.dependencytrack.csaf.CsafAggregatorDao;
import org.dependencytrack.csaf.CsafProvider;
import org.dependencytrack.csaf.CsafProviderDao;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;
import java.time.Instant;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.auth.Permissions.SYSTEM_CONFIGURATION_CREATE;
import static org.dependencytrack.auth.Permissions.SYSTEM_CONFIGURATION_DELETE;
import static org.dependencytrack.auth.Permissions.SYSTEM_CONFIGURATION_READ;
import static org.dependencytrack.auth.Permissions.SYSTEM_CONFIGURATION_UPDATE;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class CsafResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    private Handle jdbiHandle;
    private CsafAggregatorDao aggregatorDao;
    private CsafProviderDao providerDao;

    @BeforeEach
    @Override
    public void before() throws Exception {
        super.before();

        jdbiHandle = openJdbiHandle();
        aggregatorDao = jdbiHandle.attach(CsafAggregatorDao.class);
        providerDao = jdbiHandle.attach(CsafProviderDao.class);
    }

    @AfterEach
    @Override
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }

        super.after();
    }

    @Test
    public void createAggregatorShouldReturnCreatedAggregator() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_CREATE);

        Response response = jersey.target("/csaf-aggregators")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "namespace": "https://example.com",
                          "name": "test",
                          "url": "https://example.com/.well-known/csaf/aggregator.json",
                          "enabled": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation()).asString().matches(".+/csaf-aggregators/.+$");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-string}",
                  "namespace": "https://example.com",
                  "name": "test",
                  "url": "https://example.com/.well-known/csaf/aggregator.json",
                  "enabled": true,
                  "created_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    public void createAggregatorShouldReturnConflictWhenUrlAlreadyExists() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_CREATE);

        aggregatorDao.create(new CsafAggregator(
                URI.create("https://example.com/.well-known/csaf/aggregator.json"),
                URI.create("https://foo.example.com"),
                "Foo"));

        Response response = jersey.target("/csaf-aggregators")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "namespace": "https://bar.example.com",
                          "name": "Bar",
                          "url": "https://example.com/.well-known/csaf/aggregator.json",
                          "enabled": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 409,
                  "title": "Resource already exists",
                  "detail": "An aggregator with the same URL already exists."
                }
                """);
    }

    @Test
    public void getAggregatorShouldReturnAggregator() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        var aggregator = new CsafAggregator(
                URI.create("https://example.com/.well-known/csaf/aggregator.json"),
                URI.create("https://example.com"),
                "test");
        aggregator = aggregatorDao.create(aggregator);

        final Response response = jersey.target("/csaf-aggregators/" + aggregator.getId())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-string}",
                  "namespace": "https://example.com",
                  "name": "test",
                  "url": "https://example.com/.well-known/csaf/aggregator.json",
                  "enabled": false,
                  "created_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    public void getAggregatorShouldReturnNotFoundWhenDoesNotExist() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/csaf-aggregators/ca9569dd-3e81-41b2-b9dc-6bc536ad1cc7")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status": 404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void listAggregatorsShouldSupportPagination() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        for (int i = 0; i < 2; i++) {
            var aggregator = new CsafAggregator(
                    URI.create("https://%d.example.com/.well-known/csaf/aggregator.json".formatted(i)),
                    URI.create("https://%d.example.com".formatted(i)),
                    "test" + i);
            aggregator.setEnabled(true);
            aggregatorDao.create(aggregator);
        }

        Response response = jersey.target("/csaf-aggregators")
                .queryParam("limit", 1)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "aggregators": [
                    {
                      "id": "${json-unit.any-string}",
                      "namespace": "https://0.example.com",
                      "name": "test0",
                      "url": "https://0.example.com/.well-known/csaf/aggregator.json",
                      "enabled": true,
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}",
                      "next": "${json-unit.any-string}"
                    },
                    "total": {
                      "type": "EXACT",
                      "count": 2
                    }
                  }
                }
                """);

        final var nextPageUri = URI.create(
                responseJson
                        .getJsonObject("_pagination")
                        .getJsonObject("links")
                        .getString("next"));

        response = jersey.target(nextPageUri)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "aggregators": [
                    {
                      "id": "${json-unit.any-string}",
                      "namespace": "https://1.example.com",
                      "name": "test1",
                      "url": "https://1.example.com/.well-known/csaf/aggregator.json",
                      "enabled": true,
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}"
                    },
                    "total": {
                      "type": "EXACT",
                      "count": 2
                    }
                  }
                }
                """);
    }

    @Test
    public void listAggregatorsShouldSupportFilteringBySearchText() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        aggregatorDao.create(
                new CsafAggregator(
                        URI.create("https://foo.example.com/.well-known/csaf/aggregator.json"),
                        URI.create("https://foo.example.com"),
                        "Foo"));
        aggregatorDao.create(
                new CsafAggregator(
                        URI.create("https://bar.example.com/.well-known/csaf/aggregator.json"),
                        URI.create("https://bar.example.com"),
                        "Bar"));

        Response response = jersey.target("/csaf-aggregators")
                .queryParam("search_text", "fO")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "aggregators": [
                            {
                              "name": "Foo"
                            }
                          ],
                          "_pagination": {
                            "total": {
                              "count": 1
                            }
                          }
                        }
                        """);

        response = jersey.target("/csaf-aggregators")
                .queryParam("search_text", "exAM")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "aggregators": [
                            {
                              "name": "Bar"
                            },
                            {
                              "name": "Foo"
                            }
                          ],
                          "_pagination": {
                            "total": {
                              "count": 2
                            }
                          }
                        }
                        """);
    }

    @Test
    public void updateAggregatorShouldReturnUpdatedAggregator() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_UPDATE);

        final var aggregator = new CsafAggregator(
                URI.create("https://example.com/.well-known/csaf/aggregator.json"),
                URI.create("https://example.com"),
                "test");
        aggregator.setEnabled(true);
        aggregatorDao.create(aggregator);

        final Response response = jersey.target("/csaf-aggregators/%s".formatted(aggregator.getId()))
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "enabled": false
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-string}",
                  "namespace": "https://example.com",
                  "name": "test",
                  "url": "https://example.com/.well-known/csaf/aggregator.json",
                  "enabled": false,
                  "created_at": "${json-unit.any-number}",
                  "updated_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    public void deleteAggregatorShouldReturnNoContent() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_DELETE);

        final var aggregator = new CsafAggregator(
                URI.create("example.com"),
                URI.create("https://example.com"),
                "test");
        aggregator.setEnabled(true);
        aggregatorDao.create(aggregator);

        Response response = jersey.target("/csaf-aggregators/%s".formatted(aggregator.getId()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        assertThat(aggregatorDao.getById(aggregator.getId())).isNull();
    }

    @Test
    public void triggerCsafProviderDiscoveryShouldReturnAccepted() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_UPDATE);

        final var aggregator = new CsafAggregator(
                URI.create("example.com"),
                URI.create("https://example.com"),
                "test");
        aggregator.setEnabled(true);
        aggregatorDao.create(aggregator);

        final Response response = jersey.target(
                        "/csaf-aggregators/%s/provider-discovery".formatted(
                                aggregator.getId()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(202);
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    public void triggerCsafProviderDiscoveryShouldReturnNotFoundWhenAggregatorDoesNotExist() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey.target("/csaf-aggregators/e15127ce-d2a4-44f8-a037-3b19ca77c174/provider-discovery")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status": 404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void createProviderShouldReturnCreatedProvider() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_CREATE);

        Response response = jersey.target("/csaf-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "namespace": "https://example.com",
                          "name": "test",
                          "url": "https://example.com/.well-known/csaf/provider.json",
                          "enabled": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation()).asString().matches(".+/csaf-providers/.+$");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-string}",
                  "namespace": "https://example.com",
                  "name": "test",
                  "url": "https://example.com/.well-known/csaf/provider.json",
                  "enabled": true,
                  "created_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    public void createProviderShouldReturnConflictWhenUrlAlreadyExists() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_CREATE);

        providerDao.create(new CsafProvider(
                URI.create("https://example.com/.well-known/csaf/provider.json"),
                URI.create("https://foo.example.com"),
                "Foo"));

        Response response = jersey.target("/csaf-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "namespace": "https://bar.example.com",
                          "name": "Bar",
                          "url": "https://example.com/.well-known/csaf/provider.json",
                          "enabled": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 409,
                  "title": "Resource already exists",
                  "detail": "A provider with the same URL already exists."
                }
                """);
    }

    @Test
    public void getProviderShouldReturnProvider() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        var provider = new CsafProvider(
                URI.create("https://example.com/.well-known/csaf/provider.json"),
                URI.create("https://example.com"),
                "test");
        provider = providerDao.create(provider);

        final Response response = jersey.target("/csaf-providers/" + provider.getId())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-string}",
                  "namespace": "https://example.com",
                  "name": "test",
                  "url": "https://example.com/.well-known/csaf/provider.json",
                  "enabled": false,
                  "created_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    public void getProviderShouldReturnNotFoundWhenDoesNotExist() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/csaf-providers/ca9569dd-3e81-41b2-b9dc-6bc536ad1cc7")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status": 404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void listProvidersShouldSupportPagination() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        for (int i = 0; i < 2; i++) {
            var provider = new CsafProvider(
                    URI.create("https://%d.example.com/.well-known/csaf/provider.json".formatted(i)),
                    URI.create("https://%d.example.com".formatted(i)),
                    "test" + i);
            provider.setEnabled(true);
            providerDao.create(provider);
        }

        Response response = jersey.target("/csaf-providers")
                .queryParam("limit", 1)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "providers": [
                    {
                      "id": "${json-unit.any-string}",
                      "namespace": "https://0.example.com",
                      "name": "test0",
                      "url": "https://0.example.com/.well-known/csaf/provider.json",
                      "enabled": true,
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}",
                      "next": "${json-unit.any-string}"
                    },
                    "total": {
                      "type": "EXACT",
                      "count": 2
                    }
                  }
                }
                """);

        final var nextPageUri = URI.create(
                responseJson
                        .getJsonObject("_pagination")
                        .getJsonObject("links")
                        .getString("next"));

        response = jersey.target(nextPageUri)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "providers": [
                    {
                      "id": "${json-unit.any-string}",
                      "namespace": "https://1.example.com",
                      "name": "test1",
                      "url": "https://1.example.com/.well-known/csaf/provider.json",
                      "enabled": true,
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}"
                    },
                    "total": {
                      "type": "EXACT",
                      "count": 2
                    }
                  }
                }
                """);
    }

    @Test
    public void listProvidersShouldSupportFilteringBySearchText() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        providerDao.create(
                new CsafProvider(
                        URI.create("https://foo.example.com/.well-known/csaf/provider.json"),
                        URI.create("https://foo.example.com"),
                        "Foo"));
        providerDao.create(
                new CsafProvider(
                        URI.create("https://bar.example.com/.well-known/csaf/provider.json"),
                        URI.create("https://bar.example.com"),
                        "Bar"));

        Response response = jersey.target("/csaf-providers")
                .queryParam("search_text", "fO")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "providers": [
                            {
                              "name": "Foo"
                            }
                          ],
                          "_pagination": {
                            "total": {
                              "count": 1
                            }
                          }
                        }
                        """);

        response = jersey.target("/csaf-providers")
                .queryParam("search_text", "exAM")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "providers": [
                            {
                              "name": "Bar"
                            },
                            {
                              "name": "Foo"
                            }
                          ],
                          "_pagination": {
                            "total": {
                              "count": 2
                            }
                          }
                        }
                        """);
    }

    @Test
    public void listProvidersShouldSupportFilteringByDiscovered() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_READ);

        var aggregator = new CsafAggregator(
                URI.create("https://example.com/.well-known/csaf/aggregator.json"),
                URI.create("https://example.com"),
                "test");
        aggregator = aggregatorDao.create(aggregator);

        final var discoveredProvider = new CsafProvider(
                URI.create("https://foo.example.com/.well-known/csaf/provider.json"),
                URI.create("https://foo.example.com"),
                "Foo");
        discoveredProvider.setDiscoveredFrom(aggregator.getId());
        discoveredProvider.setDiscoveredAt(Instant.now());
        providerDao.create(discoveredProvider);

        providerDao.create(
                new CsafProvider(
                        URI.create("https://bar.example.com/.well-known/csaf/provider.json"),
                        URI.create("https://bar.example.com"),
                        "Bar"));

        Response response = jersey.target("/csaf-providers")
                .queryParam("discovered", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "providers": [
                            {
                              "name": "Foo"
                            }
                          ],
                          "_pagination": {
                            "total": {
                              "count": 1
                            }
                          }
                        }
                        """);

        response = jersey.target("/csaf-providers")
                .queryParam("discovered", "false")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "providers": [
                            {
                              "name": "Bar"
                            }
                          ],
                          "_pagination": {
                            "total": {
                              "count": 1
                            }
                          }
                        }
                        """);
    }

    @Test
    public void updateProviderShouldReturnUpdatedProvider() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_UPDATE);

        final var provider = new CsafProvider(
                URI.create("https://example.com/.well-known/csaf/provider.json"),
                URI.create("https://example.com"),
                "test");
        provider.setEnabled(true);
        providerDao.create(provider);

        Response response = jersey.target("/csaf-providers/%s".formatted(provider.getId()))
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "enabled": false
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-string}",
                  "namespace": "https://example.com",
                  "name": "test",
                  "url": "https://example.com/.well-known/csaf/provider.json",
                  "enabled": false,
                  "created_at": "${json-unit.any-number}",
                  "updated_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    public void deleteProviderShouldReturnNoContent() {
        initializeWithPermissions(SYSTEM_CONFIGURATION_DELETE);

        final var provider = new CsafProvider(
                URI.create("example.com"),
                URI.create("https://example.com"),
                "test");
        provider.setEnabled(true);
        providerDao.create(provider);

        final Response response = jersey.target("/csaf-providers/%s".formatted(provider.getId()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        assertThat(providerDao.getById(provider.getId())).isNull();
    }

}
