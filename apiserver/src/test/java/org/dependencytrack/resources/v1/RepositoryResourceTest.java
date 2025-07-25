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
import alpine.server.filters.AuthenticationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Date;
import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class RepositoryResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(RepositoryResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultRepositories);
    }

    @Test
    public void getRepositoriesTest() {
        Response response = jersey.target(V1_REPOSITORY).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(17), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(17, json.size());
        for (int i = 0; i < json.size(); i++) {
            Assert.assertNotNull(json.getJsonObject(i).getString("type"));
            Assert.assertNotNull(json.getJsonObject(i).getString("identifier"));
            Assert.assertNotNull(json.getJsonObject(i).getString("url"));
            Assert.assertTrue(json.getJsonObject(i).getInt("resolutionOrder") > 0);
            Assert.assertTrue(json.getJsonObject(i).getBoolean("enabled"));
        }
    }

    @Test
    public void getRepositoriesByTypeTest() {
        Response response = jersey.target(V1_REPOSITORY + "/MAVEN").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(5, json.size());
        for (int i = 0; i < json.size(); i++) {
            Assert.assertEquals("MAVEN", json.getJsonObject(i).getString("type"));
            Assert.assertFalse(json.getJsonObject(i).getBoolean("authenticationRequired"));
            Assert.assertNotNull(json.getJsonObject(i).getString("identifier"));
            Assert.assertNotNull(json.getJsonObject(i).getString("url"));
            Assert.assertTrue(json.getJsonObject(i).getInt("resolutionOrder") > 0);
            Assert.assertTrue(json.getJsonObject(i).getBoolean("enabled"));
        }
    }

    @Test
    public void getRepositoryMetaComponentTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/maven/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("MAVEN", json.getString("repositoryType"));
        Assert.assertEquals("org.acme", json.getString("namespace"));
        Assert.assertEquals("example-component", json.getString("name"));
        Assert.assertEquals("2.0.0", json.getString("latestVersion"));
        Assert.assertEquals(lastCheck.getTime(), json.getJsonNumber("lastCheck").longValue());
    }

    @Test
    public void getRepositoryMetaComponentInvalidRepoTypeTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/generic/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void getRepositoryMetaComponentInvalidPurlTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "g:/g/g/g")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void getRepositoryMetaUntrackedComponentTest() {
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/maven/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The repository metadata for the specified component cannot be found.", body);
    }

    @Test
    public void createRepositoryTest() throws Exception {
        Repository repository = new Repository();
        repository.setAuthenticationRequired(true);
        repository.setEnabled(true);
        repository.setUsername("testuser");
        repository.setPassword("testPassword");
        repository.setInternal(true);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus());


        response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(18), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(18, json.size());
        Assert.assertEquals("MAVEN", json.getJsonObject(13).getString("type"));
        Assert.assertEquals("test", json.getJsonObject(13).getString("identifier"));
        Assert.assertEquals("www.foobar.com", json.getJsonObject(13).getString("url"));
        Assert.assertTrue(json.getJsonObject(13).getInt("resolutionOrder") > 0);
        Assert.assertTrue(json.getJsonObject(13).getBoolean("authenticationRequired"));
        Assert.assertEquals("testuser", json.getJsonObject(13).getString("username"));
        Assert.assertTrue(json.getJsonObject(13).getBoolean("enabled"));
    }

    @Test
    public void createRepositoryAuthFalseTest() {
        Repository repository = new Repository();
        repository.setAuthenticationRequired(false);
        repository.setEnabled(true);
        repository.setInternal(true);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus());


        response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(18), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(18, json.size());
        Assert.assertEquals("MAVEN", json.getJsonObject(13).getString("type"));
        Assert.assertEquals("test", json.getJsonObject(13).getString("identifier"));
        Assert.assertEquals("www.foobar.com", json.getJsonObject(13).getString("url"));
        Assert.assertTrue(json.getJsonObject(13).getInt("resolutionOrder") > 0);
        Assert.assertFalse(json.getJsonObject(13).getBoolean("authenticationRequired"));
        Assert.assertTrue(json.getJsonObject(13).getBoolean("enabled"));

    }

    @Test
    public void updateRepositoryTest() throws Exception {
        Repository repository = new Repository();
        repository.setAuthenticationRequired(true);
        repository.setEnabled(true);
        repository.setUsername("testuser");
        repository.setPassword("testPassword");
        repository.setInternal(true);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus());
        try (QueryManager qm = new QueryManager()) {
            List<Repository> repositoryList = qm.getRepositories(RepositoryType.MAVEN).getList(Repository.class);
            for (Repository repository1 : repositoryList) {
                if (repository1.getIdentifier().equals("test")) {
                    repository1.setAuthenticationRequired(false);
                    response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                            .post(Entity.entity(repository1, MediaType.APPLICATION_JSON));
                    Assert.assertEquals(200, response.getStatus());
                    break;
                }
            }
            repositoryList = qm.getRepositories(RepositoryType.MAVEN).getList(Repository.class);
            for (Repository repository1 : repositoryList) {
                if (repository1.getIdentifier().equals("test")) {
                    Assert.assertFalse(repository1.isAuthenticationRequired());
                    break;
                }
            }
        }

    }

    @Test
    public void authenticationNullTest() throws Exception {
        Repository repository = new Repository();
        repository.setEnabled(true);
        repository.setInternal(true);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus());
        try (QueryManager qm = new QueryManager()) {
            List<Repository> repositoryList = qm.getRepositories(RepositoryType.MAVEN).getList(Repository.class);
            for (Repository repository1 : repositoryList) {
                if (repository1.getIdentifier().equals("test")) {
                    Assert.assertFalse(repository1.isAuthenticationRequired());
                    break;
                }
            }
            repositoryList = qm.getRepositories(RepositoryType.MAVEN).getList(Repository.class);
            for (Repository repository1 : repositoryList) {
                if (repository1.getIdentifier().equals("test")) {
                    Assert.assertFalse(repository1.isAuthenticationRequired());
                    break;
                }
            }
        }

    }
}
