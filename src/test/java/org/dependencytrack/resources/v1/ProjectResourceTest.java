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

import alpine.common.util.UuidUtil;
import alpine.event.framework.EventService;
import alpine.model.IConfigProperty.PropertyType;
import alpine.model.ManagedUser;
import alpine.model.Team;
import alpine.server.auth.JsonWebToken;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.CloneProjectEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.tasks.CloneProjectTask;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.hamcrest.CoreMatchers;
import org.json.JSONArray;
import org.junit.After;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

public class ProjectResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ProjectResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @After
    @Override
    public void after() {
        EventService.getInstance().unsubscribe(CloneProjectTask.class);
        super.after();
    }

    @Test
    public void getProjectsDefaultRequestTest() {
        for (int i = 0; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
        Assert.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("999", json.getJsonObject(0).getString("version"));
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2583
    public void getProjectsWithAclEnabledTest() {
        enablePortfolioAccessControl();
        // Create project and give access to current principal's team.
        final Project accessProject = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        accessProject.setAccessTeams(List.of(team));
        qm.persist(accessProject);

        // Create a second project that the current principal has no access to.
        qm.createProject("acme-app-b", null, "2.0.0", null, null, null, null, false);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1, json.size());
        Assert.assertEquals("acme-app-a", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("1.0.0", json.getJsonObject(0).getString("version"));
    }

    @Test
    public void getProjectsByNameRequestTest() {
        for (int i = 0; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT)
                .queryParam("name", "Acme Example")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
        Assert.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("999", json.getJsonObject(0).getString("version"));
    }

    @Test
    public void getProjectsByInvalidNameRequestTest() {
        for (int i = 0; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT)
                .queryParam("name", "blah")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(0, json.size());
    }

    @Test
    public void getProjectsByNameActiveOnlyRequestTest() {
        for (int i = 0; i < 500; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        for (int i = 500; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, new Date(), false);
        }
        Response response = jersey.target(V1_PROJECT)
                .queryParam("name", "Acme Example")
                .queryParam("excludeInactive", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(500), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
    }

    @Test
    public void getProjectLookupTest() {
        for (int i = 0; i < 500; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT + "/lookup")
                .queryParam("name", "Acme Example")
                .queryParam("version", "10")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Acme Example", json.getString("name"));
        Assert.assertEquals("10", json.getString("version"));
        Assert.assertEquals(500, json.getJsonArray("versions").size());
        Assert.assertNotNull(json.getJsonArray("versions").getJsonObject(100).getString("uuid"));
        Assert.assertNotEquals("", json.getJsonArray("versions").getJsonObject(100).getString("uuid"));
        Assert.assertEquals("100", json.getJsonArray("versions").getJsonObject(100).getString("version"));
    }

    @Test
    public void getProjectLookupNotFoundTest() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/lookup")
                .queryParam("name", "acme-app")
                .queryParam("version", "3.2.1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The project could not be found.");
    }

    @Test
    public void getProjectLookupNotPermittedTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/lookup")
                .queryParam("name", "acme-app")
                .queryParam("version", "1.2.3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(getPlainTextBody(response)).isEqualTo("Access to the specified project is forbidden");
    }

    @Test
    public void getProjectsAscOrderedRequestTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_ASC)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectsDescOrderedRequestTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_DESC)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("DEF", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectsConciseTest() {
        final var project = new Project();
        project.setGroup("com.acme");
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setClassifier(Classifier.APPLICATION);
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("foo")));

        final Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "group": "com.acme",
                            "name": "acme-app",
                            "version": "1.0.0",
                            "classifier": "APPLICATION",
                            "active": true,
                            "isLatest": false,
                            "tags": [
                              {
                                "name": "foo"
                              }
                            ],
                            "hasChildren": false
                          }
                        ]
                        """);
    }

    @Test
    public void getProjectsConciseWithAclTest() {
        enablePortfolioAccessControl();

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setInactiveSince(new Date());
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        // Only grant access to acme-app-a.
        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": false,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));
    }

    @Test
    public void getProjectsConciseEmptyTest() {
        final Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getProjectsConcisePaginationTest() {
        for (int i = 0; i < 3; i++) {
            final var project = new Project();
            project.setName("acme-app-" + (i+1));
            qm.persist(project);
        }

        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-1",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-2",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-3",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    public void getProjectsConciseFilterByNameTest() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("name", "acme")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("name", "acme-app-b")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    public void getProjectsConciseFilterByTagTest() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.bind(projectB, List.of(qm.createTag("foo")));

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("tag", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("tag", "foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "tags": [
                      {
                        "name": "foo"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    public void getProjectsConciseFilterByTeamTest() {
        enablePortfolioAccessControl();
        // Create project and give access to current principal's team.
        final var projectB= new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        projectB.addAccessTeam(team);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("team", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("team", team.getName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));
    }

    @Test
    public void getProjectsConciseOnlyRootTest() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setParent(projectA);
        projectB.setName("acme-app-b");
        projectB.setInactiveSince(new Date());
        qm.persist(projectB);

        // Should return both when onlyRoot is not set at all.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": true
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should return both when onlyRoot=false.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("onlyRoot", "false")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": true
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should return only the parent when onlyRoot=true.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("onlyRoot", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": true
                  }
                ]
                """);
    }

    @Test
    public void getProjectsConciseWithFilterByActiveTest() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setInactiveSince(new Date());
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        // Should return both when active is not set or active is false.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should return only active when active=true
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("active", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    public void getProjectsConciseWithLatestMetricsTest() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Instant now = Instant.now();
        final Instant projectMetricsOldOccurrence = now.minus(1, ChronoUnit.HOURS);
        final Instant projectMetricsLatestOccurrence = now.minus(5, ChronoUnit.MINUTES);

        final var projectMetricsOld = new ProjectMetrics();
        projectMetricsOld.setProject(project);
        projectMetricsOld.setCritical(666);
        projectMetricsOld.setFirstOccurrence(Date.from(projectMetricsOldOccurrence));
        projectMetricsOld.setLastOccurrence(Date.from(projectMetricsOldOccurrence));
        qm.persist(projectMetricsOld);

        final var projectMetricsLatest = new ProjectMetrics();
        projectMetricsLatest.setProject(project);
        projectMetricsLatest.setComponents(1);
        projectMetricsLatest.setCritical(2);
        projectMetricsLatest.setHigh(3);
        projectMetricsLatest.setLow(4);
        projectMetricsLatest.setMedium(5);
        projectMetricsLatest.setPolicyViolationsFail(6);
        projectMetricsLatest.setPolicyViolationsInfo(7);
        projectMetricsLatest.setPolicyViolationsLicenseTotal(8);
        projectMetricsLatest.setPolicyViolationsOperationalTotal(9);
        projectMetricsLatest.setPolicyViolationsSecurityTotal(10);
        projectMetricsLatest.setPolicyViolationsTotal(11);
        projectMetricsLatest.setPolicyViolationsWarn(12);
        projectMetricsLatest.setInheritedRiskScore(13.13);
        projectMetricsLatest.setUnassigned(14);
        projectMetricsLatest.setVulnerabilities(15);
        projectMetricsLatest.setFirstOccurrence(Date.from(projectMetricsLatestOccurrence));
        projectMetricsLatest.setLastOccurrence(Date.from(projectMetricsLatestOccurrence));
        qm.persist(projectMetricsLatest);

        // Should not include metrics if not explicitly requested.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should include metrics when explicitly requested.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("includeMetrics", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false,
                    "metrics": {
                      "components": 1,
                      "critical": 2,
                      "high": 3,
                      "low": 4,
                      "medium": 5,
                      "policyViolationsFail": 6,
                      "policyViolationsInfo": 7,
                      "policyViolationsLicenseTotal": 8,
                      "policyViolationsOperationalTotal": 9,
                      "policyViolationsSecurityTotal": 10,
                      "policyViolationsTotal": 11,
                      "policyViolationsWarn": 12,
                      "inheritedRiskScore": 13.13,
                      "unassigned": 14,
                      "vulnerabilities": 15
                    }
                  }
                ]
                """);
    }

    @Test
    public void getProjectChildrenConciseTest() {
        final var parentProject = new Project();
        parentProject.setGroup("com.acme");
        parentProject.setName("acme-app");
        parentProject.setVersion("1.0.0");
        parentProject.setClassifier(Classifier.APPLICATION);
        qm.persist(parentProject);

        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setGroup("com.acme");
        childProject.setName("acme-child-app");
        childProject.setVersion("2.0.0");
        childProject.setClassifier(Classifier.APPLICATION);
        qm.persist(childProject);

        qm.bind(childProject, List.of(qm.createTag("foo")));

        final Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("childProjectUuid", equalTo(childProject.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:childProjectUuid}",
                            "group": "com.acme",
                            "name": "acme-child-app",
                            "version": "2.0.0",
                            "classifier": "APPLICATION",
                            "active": true,
                            "isLatest": false,
                            "tags": [
                              {
                                "name": "foo"
                              }
                            ],
                            "hasChildren": false
                          }
                        ]
                        """);
    }

    @Test
    public void getProjectChildrenConciseWithAclTest() {
        enablePortfolioAccessControl();

        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        qm.persist(childProjectB);

        // Only grant access to acme-app.
        parentProject.addAccessTeam(team);

        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "active": true,
                    "hasChildren": false,
                    "isLatest": false,
                    "name": "acme-child-app-a",
                    "uuid": "${json-unit.any-string}"
                  },
                  {
                    "active": true,
                    "hasChildren": false,
                    "isLatest": false,
                    "name": "acme-child-app-b",
                    "uuid": "${json-unit.any-string}"
                  }
                ]
                """);

        // Additionally grant access to acme-child-app-a.
        childProjectA.addAccessTeam(team);

        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-a",
                    "active": true,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));

        // Revoke access from acme-app.
        parentProject.setAccessTeams(null);

        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getProjectChildrenConciseEmptyTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getProjectChildrenConciseWithParentNotExistsTest() {
        final Response response = jersey.target(V1_PROJECT + "/concise/6ce40fad-0cff-427a-86ce-acb248872b5b/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getProjectChildrenConcisePaginationTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        for (int i = 0; i < 3; i++) {
            final var childProject = new Project();
            childProject.setParent(parentProject);
            childProject.setName("acme-child-app-" + (i+1));
            qm.persist(childProject);
        }

        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-1",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-2",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-3",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    public void getProjectChildrenConciseFilterByNameTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        childProjectB.setInactiveSince(new Date());
        qm.persist(childProjectB);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("name", "acme")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("name", "acme-child-app-b")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    public void getProjectChildrenConciseFilterByTagTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        qm.persist(childProjectB);

        qm.bind(childProjectB, List.of(qm.createTag("foo")));

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("tag", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("tag", "foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": true,
                    "isLatest": false,
                    "tags": [
                      {
                        "name": "foo"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    public void getProjectChildrenConciseFilterByTeamTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        qm.persist(childProjectB);

        childProjectB.addAccessTeam(team);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("team", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("team", team.getName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": true,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));
    }


    @Test
    public void getProjectChildrenConciseWithLatestMetricsTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-child-app");
        qm.persist(childProject);

        final Instant now = Instant.now();
        final Instant projectMetricsOldOccurrence = now.minus(1, ChronoUnit.HOURS);
        final Instant projectMetricsLatestOccurrence = now.minus(5, ChronoUnit.MINUTES);

        final var projectMetricsOld = new ProjectMetrics();
        projectMetricsOld.setProject(childProject);
        projectMetricsOld.setCritical(666);
        projectMetricsOld.setFirstOccurrence(Date.from(projectMetricsOldOccurrence));
        projectMetricsOld.setLastOccurrence(Date.from(projectMetricsOldOccurrence));
        qm.persist(projectMetricsOld);

        final var projectMetricsLatest = new ProjectMetrics();
        projectMetricsLatest.setProject(childProject);
        projectMetricsLatest.setComponents(1);
        projectMetricsLatest.setCritical(2);
        projectMetricsLatest.setHigh(3);
        projectMetricsLatest.setLow(4);
        projectMetricsLatest.setMedium(5);
        projectMetricsLatest.setPolicyViolationsFail(6);
        projectMetricsLatest.setPolicyViolationsInfo(7);
        projectMetricsLatest.setPolicyViolationsLicenseTotal(8);
        projectMetricsLatest.setPolicyViolationsOperationalTotal(9);
        projectMetricsLatest.setPolicyViolationsSecurityTotal(10);
        projectMetricsLatest.setPolicyViolationsTotal(11);
        projectMetricsLatest.setPolicyViolationsWarn(12);
        projectMetricsLatest.setInheritedRiskScore(13.13);
        projectMetricsLatest.setUnassigned(14);
        projectMetricsLatest.setVulnerabilities(15);
        projectMetricsLatest.setFirstOccurrence(Date.from(projectMetricsLatestOccurrence));
        projectMetricsLatest.setLastOccurrence(Date.from(projectMetricsLatestOccurrence));
        qm.persist(projectMetricsLatest);

        // Should not include metrics if not explicitly requested.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should include metrics when explicitly requested.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("includeMetrics", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false,
                    "metrics": {
                      "components": 1,
                      "critical": 2,
                      "high": 3,
                      "low": 4,
                      "medium": 5,
                      "policyViolationsFail": 6,
                      "policyViolationsInfo": 7,
                      "policyViolationsLicenseTotal": 8,
                      "policyViolationsOperationalTotal": 9,
                      "policyViolationsSecurityTotal": 10,
                      "policyViolationsTotal": 11,
                      "policyViolationsWarn": 12,
                      "inheritedRiskScore": 13.13,
                      "unassigned": 14,
                      "vulnerabilities": 15
                    }
                  }
                ]
                """);
    }

    @Test
    public void getProjectByUuidTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        parentProject.setVersion("1.0.0");
        qm.persist(parentProject);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setParent(parentProject);
        qm.persist(project);

        final var childProject = new Project();
        childProject.setName("acme-app-child");
        childProject.setVersion("1.0.0");
        childProject.setParent(project);
        childProject.setInactiveSince(new Date());
        qm.persist(childProject);

        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("parentUuid", equalTo(parentProject.getUuid().toString()))
                .withMatcher("childUuid", equalTo(childProject.getUuid().toString()))
                .isEqualTo("""
                        {
                          "name": "acme-app",
                          "version": "1.0.0",
                          "uuid": "${json-unit.matches:projectUuid}",
                          "parent": {
                            "name": "acme-app-parent",
                            "version": "1.0.0",
                            "uuid": "${json-unit.matches:parentUuid}"
                          },
                          "children": [
                            {
                              "name": "acme-app-child",
                              "version": "1.0.0",
                              "uuid": "${json-unit.matches:childUuid}",
                              "isLatest": false,
                              "active": false,
                              "inactiveSince": "${json-unit.any-number}"
                            }
                          ],
                          "properties": [],
                          "tags": [],
                          "isLatest": false,
                          "active":true,
                          "versions": [
                            {
                              "uuid": "${json-unit.matches:projectUuid}",
                              "version": "1.0.0",
                              "active": true
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void getProjectByUuidNotPermittedTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(getPlainTextBody(response)).isEqualTo("Access to the specified project is forbidden");
    }

    @Test
    public void getProjectByInvalidUuidTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getProjectByTagTest() {
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("production");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/tag/" + "production")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectByCaseInsensitiveTagTest() {
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("PRODUCTION");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/tag/" + "production")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectByUnknownTagTest() {
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("production");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/tag/" + "stable")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(0, json.size());
    }

    @Test
    public void createProjectTest() throws Exception {
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        project.setDescription("Test project");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Acme Example", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test project", json.getString("description"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));

        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() == 1, Duration.ofSeconds(5));
        final org.dependencytrack.proto.notification.v1.Notification projectNotification = deserializeValue(KafkaTopics.NOTIFICATION_PROJECT_CREATED, kafkaMockProducer.history().get(0));
        assertThat(projectNotification).isNotNull();
        assertThat(projectNotification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(projectNotification.getGroup()).isEqualTo(GROUP_PROJECT_CREATED);
        assertThat(projectNotification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(projectNotification.getTitle()).isEqualTo(NotificationConstants.Title.PROJECT_CREATED);
    }

    @Test
    public void createProjectDuplicateTest() {
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A project with the specified name already exists.", body);
    }

    @Test
    public void createProjectInactiveParentTest() {
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        parentProject.setVersion("1.0.0");
        parentProject.setInactiveSince(new Date());
        qm.persist(parentProject);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "parent": {
                            "uuid": "%s"
                          },
                          "name": "acme-app",
                          "version": "1.2.3"
                        }
                        """.formatted(parentProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(getPlainTextBody(response)).isEqualTo("An inactive Parent cannot be selected as parent");
    }

    @Test
    public void createProjectDuplicateRaceConditionTest() throws Exception {
        final ExecutorService executor = Executors.newFixedThreadPool(10);
        final var countDownLatch = new CountDownLatch(1);

        final var responses = new ArrayBlockingQueue<Response>(50);
        for (int i = 0; i < 50; i++) {
            executor.submit(() -> {
                try {
                    countDownLatch.await();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }

                final Response response = jersey.target(V1_PROJECT)
                        .request()
                        .header(X_API_KEY, apiKey)
                        .put(Entity.entity("""
                                {
                                  "name": "acme-app",
                                  "version": "1.0.0"
                                }
                                """, MediaType.APPLICATION_JSON));
                responses.offer(response);
            });
        }

        countDownLatch.countDown();
        executor.shutdown();
        assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();

        assertThat(responses).hasSize(50);
        assertThat(responses).satisfiesOnlyOnce(response -> assertThat(response.getStatus()).isEqualTo(201));
        assertThat(responses.stream().map(Response::getStatus).filter(status -> status != 201)).containsOnly(409);
    }

    @Test
    public void createProjectEmptyTest() {
        Project project = new Project();
        project.setName(" ");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void updateProjectTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        project.setDescription("Test project");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test project", json.getString("description"));
    }

    @Test
    public void updateProjectNotFoundTest() {
        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        {
                          "uuid": "317fe231-01a4-4435-92ad-abd01017bb1a",
                          "name": "acme-app",
                          "version": "1.2.3"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the project could not be found.");
    }

    @Test
    public void updateProjectNotPermittedTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        {
                          "uuid": "%s",
                          "name": "acme-app-foo"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(getPlainTextBody(response)).isEqualTo("Access to the specified project is forbidden");
    }

    @Test
    public void updateProjectTagsTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);

        final var jsonProject = new Project();
        jsonProject.setUuid(p1.getUuid());
        jsonProject.setName(p1.getName());
        jsonProject.setVersion(p1.getVersion());
        jsonProject.setTags(Stream.of("tag1", "tag2", "tag3").map(name -> {
            var t = new Tag();
            t.setName(name);
            return t;
        }).collect(Collectors.toList()));

        // update the 1st time and add another tag
        var response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        var json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(p1.getName(), json.getString("name"));
        Assert.assertEquals(p1.getVersion(), json.getString("version"));
        Assert.assertFalse(json.containsKey("description"));
        var jsonTags = json.getJsonArray("tags");
        Assert.assertEquals(3, jsonTags.size());
        Assert.assertEquals("tag1", jsonTags.get(0).asJsonObject().getString("name"));
        Assert.assertEquals("tag2", jsonTags.get(1).asJsonObject().getString("name"));
        Assert.assertEquals("tag3", jsonTags.get(2).asJsonObject().getString("name"));

        // and update again with the same tags ... issue #1165
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        json = parseJsonObject(response);
        jsonTags = json.getJsonArray("tags");
        Assert.assertEquals(3, jsonTags.size());
        Assert.assertEquals("tag1", jsonTags.get(0).asJsonObject().getString("name"));
        Assert.assertEquals("tag2", jsonTags.get(1).asJsonObject().getString("name"));
        Assert.assertEquals("tag3", jsonTags.get(2).asJsonObject().getString("name"));

        // and finally delete one of the tags
        jsonProject.getTags().remove(0);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        json = parseJsonObject(response);
        jsonTags = json.getJsonArray("tags");
        Assert.assertEquals(2, jsonTags.size());
        Assert.assertEquals("tag2", jsonTags.get(0).asJsonObject().getString("name"));
        Assert.assertEquals("tag3", jsonTags.get(1).asJsonObject().getString("name"));
    }

    @Test
    public void updateProjectEmptyNameTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        project.setName(" ");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void updateProjectDuplicateTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project project = qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        project = qm.detach(Project.class, project.getId());
        project.setName("ABC");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A project with the specified name and version already exists.", body);
    }

    @Test
    public void deleteProjectTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteProjectInvalidUuidTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void patchProjectNotModifiedTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);

        final var jsonProject = new Project();
        jsonProject.setDescription(p1.getDescription());
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assert.assertEquals(Response.Status.NOT_MODIFIED.getStatusCode(), response.getStatus());
        Assert.assertEquals(p1, qm.getObjectByUuid(Project.class, p1.getUuid()));
    }

    @Test
    public void patchProjectNameVersionConflictTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);
        qm.createProject("ABC", "Test project", "0.9", null, null, null, null, false);
        final var jsonProject = new Project();
        jsonProject.setVersion("0.9");
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assert.assertEquals(Response.Status.CONFLICT.getStatusCode(), response.getStatus());
        Assert.assertEquals(p1, qm.getObjectByUuid(Project.class, p1.getUuid()));
    }

    @Test
    public void patchProjectNotFoundTest() {
        final var response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(new Project()));
        Assert.assertEquals(Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
    }

    @Test
    public void patchProjectNotPermittedTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json("""
                        {
                          "name": "acme-app-foo"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(getPlainTextBody(response)).isEqualTo("Access to the specified project is forbidden");
    }

    @Test
    public void patchProjectParentTest() {
        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        final Project project = qm.createProject("DEF", null, "2.0", null, parent, null, null, false);
        final Project newParent = qm.createProject("GHI", null, "3.0", null, null, null, null, false);

        final JsonObject jsonProject = Json.createObjectBuilder()
                .add("parent", Json.createObjectBuilder()
                        .add("uuid", newParent.getUuid().toString()))
                .build();

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject.toString()));

        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", CoreMatchers.equalTo(project.getUuid().toString()))
                .withMatcher("parentProjectUuid", CoreMatchers.equalTo(newParent.getUuid().toString()))
                .isEqualTo("""
                        {
                          "name": "DEF",
                          "version": "2.0",
                          "uuid": "${json-unit.matches:projectUuid}",
                          "parent": {
                            "name": "GHI",
                            "version": "3.0",
                            "uuid": "${json-unit.matches:parentProjectUuid}"
                          },
                          "properties": [],
                          "tags": [],
                          "isLatest": false,
                          "active": true
                        }
                        """);

        // Ensure the parent was updated.
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getParent()).isNotNull();
        assertThat(project.getParent().getUuid()).isEqualTo(newParent.getUuid());
    }

    @Test
    public void patchProjectExternalReferencesTest() {
        final var project = qm.createProject("referred-project", "ExtRef test project", "1.0", null, null, null, null, false);
        final var ref1 = new ExternalReference();
        ref1.setType(org.cyclonedx.model.ExternalReference.Type.VCS);
        ref1.setUrl("https://github.com/DependencyTrack/awesomeness");
        final var ref2 = new ExternalReference();
        ref2.setType(org.cyclonedx.model.ExternalReference.Type.WEBSITE);
        ref2.setUrl("https://dependencytrack.org");
        ref2.setComment("Worth a visit!");
        final var externalReferences = List.of(ref1, ref2);
        final var jsonProject = new Project();
        jsonProject.setExternalReferences(externalReferences);

        final var response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));

        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        final var json = parseJsonObject(response);
        final var patchedExternalReferences = json.getJsonArray("externalReferences");
        Assert.assertEquals(2, patchedExternalReferences.size());
        final var patchedRef1 = patchedExternalReferences.getJsonObject(0);
        final var patchedRef2 = patchedExternalReferences.getJsonObject(1);
        Assert.assertEquals("vcs", patchedRef1.getString("type"));
        Assert.assertEquals("https://github.com/DependencyTrack/awesomeness", patchedRef1.getString("url"));
        Assert.assertEquals("website", patchedRef2.getString("type"));
        Assert.assertEquals("https://dependencytrack.org", patchedRef2.getString("url"));
        Assert.assertEquals("Worth a visit!", patchedRef2.getString("comment"));
    }

    @Test
    public void patchProjectParentNotFoundTest() {
        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        final Project project = qm.createProject("DEF", null, "2.0", null, parent, null, null, false);

        final JsonObject jsonProject = Json.createObjectBuilder()
                .add("parent", Json.createObjectBuilder()
                        .add("uuid", UUID.randomUUID().toString()))
                .build();

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject.toString()));

        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the parent project could not be found.");

        // Ensure the parent was not modified.
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getParent()).isNotNull();
        assertThat(project.getParent().getUuid()).isEqualTo(parent.getUuid());
    }

    @Test
    public void patchProjectSuccessfullyPatchedTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);
        final var projectManufacturerContact = new OrganizationalContact();
        projectManufacturerContact.setName("manufacturerContactName");
        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("manufacturerName");
        projectManufacturer.setUrls(new String[]{"https://manufacturer.example.com"});
        projectManufacturer.setContacts(List.of(projectManufacturerContact));
        p1.setManufacturer(projectManufacturer);
        final var projectSupplierContact = new OrganizationalContact();
        projectSupplierContact.setName("supplierContactName");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("supplierName");
        projectSupplier.setUrls(new String[]{"https://supplier.example.com"});
        projectSupplier.setContacts(List.of(projectSupplierContact));
        p1.setSupplier(projectSupplier);
        qm.persist(p1);
        final var jsonProject = new Project();
        jsonProject.setInactiveSince(null);
        jsonProject.setName("new name");
        jsonProject.setPublisher("new publisher");
        jsonProject.setTags(Stream.of("tag4").map(name -> {
            var t = new Tag();
            t.setName(name);
            return t;
        }).collect(Collectors.toUnmodifiableList()));
        final var jsonProjectManufacturerContact = new OrganizationalContact();
        jsonProjectManufacturerContact.setName("newManufacturerContactName");
        final var jsonProjectManufacturer = new OrganizationalEntity();
        jsonProjectManufacturer.setName("manufacturerName");
        jsonProjectManufacturer.setUrls(new String[]{"https://manufacturer.example.com"});
        jsonProjectManufacturer.setContacts(List.of(jsonProjectManufacturerContact));
        jsonProject.setManufacturer(jsonProjectManufacturer);
        final var jsonProjectSupplierContact = new OrganizationalContact();
        jsonProjectSupplierContact.setName("newSupplierContactName");
        final var jsonProjectSupplier = new OrganizationalEntity();
        jsonProjectSupplier.setName("supplierName");
        jsonProjectSupplier.setUrls(new String[]{"https://supplier.example.com"});
        jsonProjectSupplier.setContacts(List.of(jsonProjectSupplierContact));
        jsonProject.setSupplier(jsonProjectSupplier);
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", equalTo(p1.getUuid().toString()))
                .isEqualTo("""
                        {
                          "publisher": "new publisher",
                          "manufacturer": {
                            "name": "manufacturerName",
                            "urls": [
                              "https://manufacturer.example.com"
                            ],
                            "contacts": [
                              {
                                "name": "newManufacturerContactName"
                              }
                            ]
                          },
                          "supplier": {
                            "name": "supplierName",
                            "urls": [
                              "https://supplier.example.com"
                            ],
                            "contacts": [
                              {
                                "name": "newSupplierContactName"
                              }
                            ]
                          },
                          "name": "new name",
                          "description": "Test project",
                          "version": "1.0",
                          "uuid": "${json-unit.matches:projectUuid}",
                          "properties": [],
                          "tags": [
                            {
                              "name": "tag4"
                            }
                          ],
                          "isLatest": false,
                          "active":true,
                          "children": []
                        }
                        """);
    }

    @Test
    public void getRootProjectsTest() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);
        qm.createProject("GHI", null, "1.0", null, child, null, null, false);
        Response response = jersey.target(V1_PROJECT)
                .queryParam("onlyRoot", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
        Assert.assertThrows(IndexOutOfBoundsException.class, () -> json.getJsonObject(1));
    }

    @Test
    public void getChildrenProjectsTest() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);
        qm.createProject("GHI", null, "1.0", null, parent, null, null, false);
        qm.createProject("JKL", null, "1.0", null, child, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + parent.getUuid().toString() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("DEF", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("GHI", json.getJsonObject(1).getString("name"));
    }

    @Test
    public void updateChildAsParentOfChild() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setInactiveSince(null);

        tmpProject.setParent(child);
        Assert.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    public void updateParentToInactiveWithActiveChild() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, parent, null, null, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setInactiveSince(new Date());

        Assert.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }


    @Test
    public void createProjectWithoutVersionDuplicateTest() {
        Project project = new Project();
        project.setName("Acme Example");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A project with the specified name already exists.", body);
    }

    @Test
    public void updateProjectParentToSelf() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setInactiveSince(parent.getInactiveSince());
        tmpProject.setParent(parent);

        Assert.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    public void getProjectsWithoutDescendantsOfTest() {
        Project grandParent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project parent = qm.createProject("DEF", null, "1.0", null, grandParent, null, null, false);
        Project child = qm.createProject("GHI", null, "1.0", null, parent, null, null, false);
        qm.createProject("JKL", null, "1.0", null, child, null, null, false);

        Response response = jersey.target(V1_PROJECT + "/withoutDescendantsOf/" + parent.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void cloneProjectTest() {
        EventService.getInstance().subscribe(CloneProjectEvent.class, CloneProjectTask.class);

        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("projectManufacturer");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("projectSupplier");

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setManufacturer(projectManufacturer);
        project.setSupplier(projectSupplier);
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        final ProjectProperty projectProperty = qm.createProjectProperty(project, "group", "name", "value", PropertyType.STRING, "description");

        qm.bind(project, List.of(
                qm.createTag("tag-a"),
                qm.createTag("tag-b")
        ));

        final var metadataAuthor = new OrganizationalContact();
        metadataAuthor.setName("metadataAuthor");
        final var metadataSupplier = new OrganizationalEntity();
        metadataSupplier.setName("metadataSupplier");
        final var metadata = new ProjectMetadata();
        metadata.setProject(project);
        metadata.setAuthors(List.of(metadataAuthor));
        metadata.setSupplier(metadataSupplier);
        qm.persist(metadata);

        final var componentSupplier = new OrganizationalEntity();
        componentSupplier.setName("componentSupplier");

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("2.0.0");
        componentA.setSwidTagId("swidTagId");
        componentA.setSupplier(componentSupplier);
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("2.1.0");
        qm.persist(componentB);

        final var service = new ServiceComponent();
        service.setProject(project);
        service.setName("acme-service");
        service.setVersion("3.0.0");
        qm.persist(service);

        project.setDirectDependencies(new JSONArray().put(new ComponentIdentity(componentA).toJSON()).toString());
        componentA.setDirectDependencies(new JSONArray().put(new ComponentIdentity(componentB).toJSON()).toString());

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        qm.addVulnerability(vuln, componentA, AnalyzerIdentity.INTERNAL_ANALYZER);
        final Analysis analysis = qm.makeAnalysis(componentA, vuln, AnalysisState.NOT_AFFECTED,
                AnalysisJustification.REQUIRES_ENVIRONMENT, AnalysisResponse.WILL_NOT_FIX, "details", false);
        qm.makeAnalysisComment(analysis, "comment", "commenter");

        final VulnerabilityPolicy vulnPolicy = withJdbiHandle(handle -> {
            final var policyAnalysis = new VulnerabilityPolicyAnalysis();
            policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.EXPLOITABLE);

            final var policy = new VulnerabilityPolicy();
            policy.setName("foo");
            policy.setAnalysis(policyAnalysis);
            policy.setConditions(List.of("true"));
            return handle.attach(VulnerabilityPolicyDao.class).create(policy);
        });
        useJdbiHandle(handle -> handle.createUpdate("""
                        WITH "VULN_POLICY" AS (
                          SELECT "ID"
                            FROM "VULNERABILITY_POLICY"
                           WHERE "NAME" = :policyName
                        )
                        UPDATE "ANALYSIS"
                           SET "VULNERABILITY_POLICY_ID" = (SELECT "ID" FROM "VULN_POLICY")
                         WHERE "ID" = :analysisId
                        """)
                .bind("policyName", vulnPolicy.getName())
                .bind("analysisId", analysis.getId())
                .execute());


        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "version": "1.1.0",
                          "includeACL": true,
                          "includeAuditHistory": true,
                          "includeComponents": true,
                          "includeProperties": true,
                          "includeServices": true,
                          "includeTags": true
                        }
                        """.formatted(project.getUuid())));

        assertThat(response.getStatus()).isEqualTo(202);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        UUID uuid = UUID.fromString(json.getString("token"));
        assertThat(qm.getAllWorkflowStatesForAToken(uuid)).satisfiesExactly(
                workflowState -> {
                    assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.PROJECT_CLONE);
                    assertThat(workflowState.getToken()).isEqualTo(uuid);
                    assertThat(workflowState.getParent()).isNull();
                    assertThat(workflowState.getStatus()).isEqualTo(WorkflowStatus.PENDING);
                    assertThat(workflowState.getStartedAt()).isNotNull();
                    assertThat(workflowState.getUpdatedAt()).isNotNull();
                }
        );

        await("Cloning completion")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(50))
                .untilAsserted(() -> {
                    final Project clonedProject = qm.getProject("acme-app", "1.1.0");
                    assertThat(clonedProject).isNotNull();
                    assertThat(clonedProject.getUuid()).isNotEqualTo(project.getUuid());
                    assertThat(clonedProject.getSupplier()).isNotNull();
                    assertThat(clonedProject.getSupplier().getName()).isEqualTo("projectSupplier");
                    assertThat(clonedProject.getManufacturer()).isNotNull();
                    assertThat(clonedProject.getManufacturer().getName()).isEqualTo("projectManufacturer");
                    assertThat(clonedProject.getAccessTeams()).containsOnly(team);
                    assertThatJson(clonedProject.getDirectDependencies())
                            .withMatcher("notSourceComponentUuid", not(equalTo(componentA.getUuid().toString())))
                            .isEqualTo(/* language=JSON */ """
                                    [
                                      {
                                        "objectType": "COMPONENT",
                                        "uuid": "${json-unit.matches:notSourceComponentUuid}",
                                        "name": "acme-lib-a",
                                        "version": "2.0.0",
                                        "swidTagId":"swidTagId"
                                      }
                                    ]
                                    """);

                    final List<ProjectProperty> clonedProperties = qm.getProjectProperties(clonedProject);
                    assertThat(clonedProperties).satisfiesExactly(clonedProperty -> {
                        assertThat(clonedProperty.getId()).isNotEqualTo(projectProperty.getId());
                        assertThat(clonedProperty.getGroupName()).isEqualTo("group");
                        assertThat(clonedProperty.getPropertyName()).isEqualTo("name");
                        assertThat(clonedProperty.getPropertyValue()).isEqualTo("value");
                        assertThat(clonedProperty.getPropertyType()).isEqualTo(PropertyType.STRING);
                        assertThat(clonedProperty.getDescription()).isEqualTo("description");
                    });

                    assertThat(clonedProject.getTags()).extracting(Tag::getName)
                            .containsOnly("tag-a", "tag-b");

                    final ProjectMetadata clonedMetadata = clonedProject.getMetadata();
                    assertThat(clonedMetadata).isNotNull();
                    assertThat(clonedMetadata.getAuthors())
                            .satisfiesExactly(contact -> assertThat(contact.getName()).isEqualTo("metadataAuthor"));
                    assertThat(clonedMetadata.getSupplier())
                            .satisfies(entity -> assertThat(entity.getName()).isEqualTo("metadataSupplier"));

                    assertThat(qm.getAllComponents(clonedProject)).satisfiesExactlyInAnyOrder(
                            clonedComponent -> {
                                assertThat(clonedComponent.getUuid()).isNotEqualTo(componentA.getUuid());
                                assertThat(clonedComponent.getName()).isEqualTo("acme-lib-a");
                                assertThat(clonedComponent.getVersion()).isEqualTo("2.0.0");
                                assertThat(clonedComponent.getSwidTagId()).isEqualTo("swidTagId");
                                assertThat(clonedComponent.getSupplier()).isNotNull();
                                assertThat(clonedComponent.getSupplier().getName()).isEqualTo("componentSupplier");

                                assertThat(qm.getAllVulnerabilities(clonedComponent)).containsOnly(vuln);

                                assertThat(qm.getAnalysis(clonedComponent, vuln)).satisfies(clonedAnalysis -> {
                                    assertThat(clonedAnalysis.getId()).isNotEqualTo(analysis.getId());
                                    assertThat(clonedAnalysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
                                    assertThat(clonedAnalysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.REQUIRES_ENVIRONMENT);
                                    assertThat(clonedAnalysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
                                    assertThat(clonedAnalysis.getAnalysisDetails()).isEqualTo("details");
                                    assertThat(clonedAnalysis.isSuppressed()).isFalse();
                                    assertThat(clonedAnalysis.getVulnerabilityPolicyId()).isNotNull();
                                });
                            },
                            clonedComponent -> {
                                assertThat(clonedComponent.getUuid()).isNotEqualTo(componentA.getUuid());
                                assertThat(clonedComponent.getName()).isEqualTo("acme-lib-b");
                                assertThat(clonedComponent.getVersion()).isEqualTo("2.1.0");
                            });

                    assertThat(qm.getAllServiceComponents(clonedProject)).satisfiesExactly(clonedService -> {
                        assertThat(clonedService.getUuid()).isNotEqualTo(service.getUuid());
                        assertThat(clonedService.getName()).isEqualTo("acme-service");
                        assertThat(clonedService.getVersion()).isEqualTo("3.0.0");
                    });
                });
    }

    @Test
    public void cloneProjectConflictTest() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.0.0"
                        }
                        """.formatted(project.getUuid())));

        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(getPlainTextBody(response)).isEqualTo("A project with the specified name and version already exists.");
    }

    @Test
    public void cloneProjectWithAclTest() {
        enablePortfolioAccessControl();

        final var accessProject = new Project();
        accessProject.setName("acme-app-a");
        accessProject.setVersion("1.0.0");
        accessProject.setAccessTeams(List.of(team));
        qm.persist(accessProject);

        final var noAccessProject = new Project();
        noAccessProject.setName("acme-app-b");
        noAccessProject.setVersion("2.0.0");
        qm.persist(noAccessProject);

        Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.1.0"
                        }
                        """.formatted(noAccessProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(getPlainTextBody(response)).isEqualTo("Access to the specified project is forbidden");

        response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.1.0"
                        }
                        """.formatted(accessProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(202);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
    }

    @Test
    public void validateProjectVersionsActiveInactiveTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("ABC", null, "2.0", null, null, null, new Date(), false);
        qm.createProject("ABC", null, "3.0", null, null, null, null, false);

        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals(3, json.getJsonArray("versions").size());

        Assert.assertNotNull(json.getJsonArray("versions").getJsonObject(0).getJsonString("uuid").getString());
        Assert.assertEquals("1.0", json.getJsonArray("versions").getJsonObject(0).getJsonString("version").getString());
        Assert.assertTrue(json.getJsonArray("versions").getJsonObject(0).getBoolean("active"));

        Assert.assertNotNull(json.getJsonArray("versions").getJsonObject(1).getJsonString("uuid").getString());
        Assert.assertEquals("2.0", json.getJsonArray("versions").getJsonObject(1).getJsonString("version").getString());
        Assert.assertTrue(json.getJsonArray("versions").getJsonObject(0).getBoolean("active"));

        Assert.assertNotNull(json.getJsonArray("versions").getJsonObject(2).getJsonString("uuid").getString());
        Assert.assertEquals("3.0", json.getJsonArray("versions").getJsonObject(2).getJsonString("version").getString());
        Assert.assertTrue(json.getJsonArray("versions").getJsonObject(0).getBoolean("active"));
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/4048
    public void issue4048RegressionTest() {
        final int projectsPerLevel = 10;
        final int maxDepth = 5;

        final Map<Integer, List<UUID>> projectUuidsByLevel = new HashMap<>();

        // Create multiple parent-child hierarchies of projects.
        for (int i = 0; i < maxDepth; i++) {
            final List<UUID> parentUuids = projectUuidsByLevel.get(i - 1);

            for (int j = 0; j < projectsPerLevel; j++) {
                final UUID parentUuid = i > 0 ? parentUuids.get(j) : null;

                final JsonObjectBuilder requestBodyBuilder = Json.createObjectBuilder()
                        .add("name", "project-%d-%d".formatted(i, j))
                        .add("version", "%d.%d".formatted(i, j));
                if (parentUuid != null) {
                    requestBodyBuilder.add("parent", Json.createObjectBuilder()
                            .add("uuid", parentUuid.toString()));
                }

                final Response response = jersey.target(V1_PROJECT)
                        .request()
                        .header(X_API_KEY, apiKey)
                        .put(Entity.json(requestBodyBuilder.build().toString()));
                assertThat(response.getStatus()).isEqualTo(201);
                final JsonObject jsonResponse = parseJsonObject(response);

                projectUuidsByLevel.compute(i, (ignored, uuids) -> {
                    final UUID uuid = UUID.fromString(jsonResponse.getString("uuid"));
                    if (uuids == null) {
                        return new ArrayList<>(List.of(uuid));
                    }

                    uuids.add(uuid);
                    return uuids;
                });
            }
        }

        // Pick out the UUIDs of projects that should have a parent (i.e. level 1 or above).
        final List<UUID> childUuids = projectUuidsByLevel.entrySet().stream()
                .filter(entry -> entry.getKey() > 0)
                .map(Map.Entry::getValue)
                .flatMap(List::stream)
                .toList();

        // Create a [uuid -> level] mapping for better assertion failure reporting.
        final Map<UUID, Integer> levelByChildUuid = projectUuidsByLevel.entrySet().stream()
                .filter(entry -> entry.getKey() > 0)
                .flatMap(entry -> {
                    final Integer level = entry.getKey();
                    return entry.getValue().stream().map(uuid -> Map.entry(uuid, level));
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        // Request all child projects individually.
        // Ensure that the parent field is populated for all of them.
        for (final UUID uuid : childUuids) {
            final Response response = jersey.target(V1_PROJECT + "/" + uuid)
                    .request()
                    .header(X_API_KEY, apiKey)
                    .get();
            assertThat(response.getStatus()).isEqualTo(200);
            final JsonObject json = parseJsonObject(response);
            assertThat(json.getJsonObject("parent"))
                    .withFailMessage("Parent missing on level: " + levelByChildUuid.get(uuid))
                    .isNotEmpty();
        }
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/4413
    public void cloneProjectWithBrokenDependencyGraphTest() {
        EventService.getInstance().subscribe(CloneProjectEvent.class, CloneProjectTask.class);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setDirectDependencies("[{\"uuid\":\"d6b6f140-f547-4fe2-a98c-f4942ad51f86\"}]");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        component.setDirectDependencies("[{\"uuid\":\"61503628-d2a2-447b-b99c-701b9d492cbd\"}]");
        qm.persist(component);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "version": "1.1.0",
                          "includeComponents": true,
                          "includeServices": true
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(202);

        await("Cloning completion")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(50))
                .untilAsserted(() -> {
                    final Project clonedProject = qm.getProject("acme-app", "1.1.0");
                    assertThat(clonedProject).isNotNull();
                });

        final Project clonedProject = qm.getProject("acme-app", "1.1.0");
        assertThat(clonedProject.getDirectDependencies()).isEqualTo(
                "[{\"uuid\": \"d6b6f140-f547-4fe2-a98c-f4942ad51f86\"}]");

        assertThat(qm.getAllComponents(clonedProject).getFirst().getDirectDependencies()).isEqualTo(
                "[{\"uuid\": \"61503628-d2a2-447b-b99c-701b9d492cbd\"}]");
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3883
    public void issue3883RegressionTest() {
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "name": "acme-app-parent",
                          "version": "1.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final String parentProjectUuid = parseJsonObject(response).getString("uuid");

        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "name": "acme-app",
                          "version": "1.0.0",
                          "parent": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(parentProjectUuid)));
        assertThat(response.getStatus()).isEqualTo(201);
        final String childProjectUuid = parseJsonObject(response).getString("uuid");

        response = jersey.target(V1_PROJECT + "/" + parentProjectUuid)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "name": "acme-app-parent",
                  "version": "1.0.0",
                  "classifier": "APPLICATION",
                  "uuid": "${json-unit.any-string}",
                  "children": [
                    {
                      "name": "acme-app",
                      "version": "1.0.0",
                      "classifier": "APPLICATION",
                      "uuid": "${json-unit.any-string}",
                      "isLatest": false,
                      "active": true
                    }
                  ],
                  "properties": [],
                  "tags": [],
                  "isLatest": false,
                  "active": true,
                  "versions": [
                    {
                      "uuid": "${json-unit.any-string}",
                      "version": "1.0.0",
                      "active": true
                    }
                  ]
                }
                """);

        response = jersey.target(V1_PROJECT + "/" + childProjectUuid)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "name": "acme-app",
                  "version": "1.0.0",
                  "classifier": "APPLICATION",
                  "uuid": "${json-unit.any-string}",
                  "parent": {
                    "name": "acme-app-parent",
                    "version": "1.0.0",
                    "uuid": "${json-unit.any-string}"
                  },
                  "children": [],
                  "properties": [],
                  "tags": [],
                  "isLatest": false,
                  "active": true,
                  "versions": [
                    {
                      "uuid": "${json-unit.any-string}",
                      "version": "1.0.0",
                      "active": true
                    }
                  ]
                }
                """);
    }

    @Test
    public void createProjectAsLatestTest() {
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure initial value is false when not specified
        Assert.assertFalse(json.getBoolean("isLatest"));

        project.setVersion("2.0");
        project.setIsLatest(true);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure value of latest version is true when specified
        Assert.assertTrue(json.getBoolean("isLatest"));
        String v20uuid = json.getString("uuid");

        project.setVersion("2.1");
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure value of latest version is true when specified
        Assert.assertTrue(json.getBoolean("isLatest"));
        // ensure v2.0 is no longer latest
        Assert.assertFalse(qm.getProject(v20uuid).isLatest());
    }

    @Test
    public void createProjectAsLatestWithACLTest() {
        enablePortfolioAccessControl();

        final var accessProject = new Project();
        accessProject.setName("acme-app-a");
        accessProject.setVersion("1.0.0");
        accessProject.setIsLatest(true);
        accessProject.setAccessTeams(List.of(team));
        qm.persist(accessProject);

        final var noAccessProject = new Project();
        noAccessProject.setName("acme-app-b");
        noAccessProject.setVersion("2.0.0");
        noAccessProject.setIsLatest(true);
        qm.persist(noAccessProject);

        Project project = new Project();
        project.setName(accessProject.getName());
        project.setVersion("1.0.1");
        project.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertTrue(json.getBoolean("isLatest"));

        project.setName(noAccessProject.getName());
        project.setVersion("3.0.0");
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void createProjectAsInactiveTest() {
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure initial value is false when not specified
        Assert.assertTrue(json.getBoolean("active"));

        project.setVersion("2.0");
        project.setInactiveSince(new Date());
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure value of latest version is true when specified
        Assert.assertFalse(json.getBoolean("active"));
    }

    @Test
    public void updateProjectAsLatestTest() {
        // create project not as latest
        Project project = qm.createProject("ABC", null, "1.0", null, null, null,
                null, false, false);

        // make it latest by update
        var jsonProject = qm.detach(project);
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertTrue(json.getBoolean("isLatest"));

        // add another project version, "forget" to make it latest
        final Project newProject = qm.createProject("ABC", null, "1.0.1", null, null, null,
                null, false, false);
        // make the new version latest afterwards via update
        jsonProject = qm.detach(newProject);
        jsonProject.setIsLatest(true);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure is now latest
        Assert.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest
        Assert.assertFalse(qm.getProject(project.getName(), project.getVersion()).isLatest());
    }

    @Test
    public void updateProjectAsLatestWithACLAndAccessTest() {
        enablePortfolioAccessControl();

        final var accessLatestProject = new Project();
        accessLatestProject.setName("acme-app-a");
        accessLatestProject.setVersion("1.0.0");
        accessLatestProject.setIsLatest(true);
        accessLatestProject.setAccessTeams(List.of(team));
        qm.persist(accessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(List.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update
        final var jsonProject = qm.detach(accessNotLatestProject);
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure is now latest
        Assert.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest (bypass db cache)
        qm.getPersistenceManager().refreshAll();
        Assert.assertFalse(qm.getProject(accessLatestProject.getName(), accessLatestProject.getVersion()).isLatest());
    }

    @Test
    public void updateProjectAsLatestWithACLAndNoAccessTest() {
        enablePortfolioAccessControl();

        final var noAccessLatestProject = new Project();
        noAccessLatestProject.setName("acme-app-a");
        noAccessLatestProject.setVersion("1.0.0");
        noAccessLatestProject.setIsLatest(true);
        qm.persist(noAccessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(List.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update (but have no access to old latest)
        final var jsonProject = qm.detach(accessNotLatestProject);
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assert.assertEquals(403, response.getStatus(), 0);
        // ensure old is still latest
        Assert.assertTrue(qm.getProject(noAccessLatestProject.getName(), noAccessLatestProject.getVersion()).isLatest());
    }

    @Test
    public void patchProjectAsLatestTest() {
        // create project not as latest
        Project project = qm.createProject("ABC", null, "1.0", null, null, null,
                null, false, false);

        // make it latest by patch
        var jsonProject = new Project();
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertTrue(json.getBoolean("isLatest"));

        // add another project version, "forget" to make it latest
        final Project newProject = qm.createProject("ABC", null, "1.0.1", null, null, null,
                null, false, false);
        // make the new version latest afterwards via update
        jsonProject = new Project();
        jsonProject.setIsLatest(true);
        response = jersey.target(V1_PROJECT + "/" + newProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assert.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure is now latest
        Assert.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest
        Assert.assertFalse(qm.getProject(project.getName(), project.getVersion()).isLatest());
    }

    @Test
    public void patchProjectAsLatestWithACLAndAccessTest() {
        enablePortfolioAccessControl();

        final var accessLatestProject = new Project();
        accessLatestProject.setName("acme-app-a");
        accessLatestProject.setVersion("1.0.0");
        accessLatestProject.setIsLatest(true);
        accessLatestProject.setAccessTeams(List.of(team));
        qm.persist(accessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(List.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update
        final var jsonProject = new Project();
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT + "/" + accessNotLatestProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure is now latest
        Assert.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest (bypass db cache)
        qm.getPersistenceManager().refreshAll();
        Assert.assertFalse(qm.getProject(accessLatestProject.getName(), accessLatestProject.getVersion()).isLatest());
    }

    @Test
    public void patchProjectAsLatestWithACLAndNoAccessTest() {
        enablePortfolioAccessControl();

        final var noAccessLatestProject = new Project();
        noAccessLatestProject.setName("acme-app-a");
        noAccessLatestProject.setVersion("1.0.0");
        noAccessLatestProject.setIsLatest(true);
        qm.persist(noAccessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(List.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update (but have no access to old latest)
        final var jsonProject = new Project();
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT + "/" + accessNotLatestProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assert.assertEquals(403, response.getStatus(), 0);
        // ensure old is still latest
        qm.getPersistenceManager().refreshAll();
        Assert.assertTrue(qm.getProject(noAccessLatestProject.getName(), noAccessLatestProject.getVersion()).isLatest());
    }

    @Test
    public void cloneProjectAsLatestTest() {
        EventService.getInstance().subscribe(CloneProjectEvent.class, CloneProjectTask.class);

        final var project = new Project();
        project.setName("acme-app-a");
        project.setVersion("1.0.0");
        project.setIsLatest(true);
        qm.persist(project);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.1.0",
                          "makeCloneLatest": true
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(202);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));

        await("Cloning completion")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(50))
                .untilAsserted(() -> {
                    final Project clonedProject = qm.getProject("acme-app-a", "1.1.0");
                    assertThat(clonedProject).isNotNull();
                    assertThat(clonedProject.isLatest()).isTrue();

                    // ensure source is no longer latest
                    qm.getPersistenceManager().refresh(project);
                    assertThat(project.isLatest()).isFalse();
                });
    }

    @Test
    public void getLatestProjectTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        qm.createProject("Acme Example", null, "1.0.2", null, null, null, null, true, false);
        qm.createProject("Different project", null, "1.0.3", null, null, null, null, true, false);

        Response response = jersey.target(V1_PROJECT_LATEST + "Acme Example")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Acme Example", json.getString("name"));
        Assert.assertEquals("1.0.2", json.getString("version"));
    }

    @Test
    public void getLatestProjectWithAclEnabledTest() {
        enablePortfolioAccessControl();

        // Create project and give access to current principal's team.
        Project accessProject = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false, false);
        accessProject.setAccessTeams(List.of(team));
        qm.persist(accessProject);

        accessProject = qm.createProject("acme-app-a", null, "1.0.2", null, null, null, null, true, false);
        accessProject.setAccessTeams(List.of(team));
        qm.persist(accessProject);

        final Response response = jersey.target(V1_PROJECT_LATEST + "acme-app-a")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("acme-app-a", json.getString("name"));
        Assert.assertEquals("1.0.2", json.getString("version"));
    }

    @Test
    public void getLatestProjectWithAclEnabledNoAccessTest() {
        enablePortfolioAccessControl();

        // Create projects and give NO access
        qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false, false);
        qm.createProject("acme-app-a", null, "1.0.2", null, null, null, null, true, false);

        final Response response = jersey.target(V1_PROJECT_LATEST + "acme-app-a")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    public void createProjectAsUserWithAclEnabledAndExistingTeamByUuidTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userJwt = new JsonWebToken().createToken(testUser);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userJwt)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "properties": [],
                          "tags": [],
                          "active": true
                        }
                        """);

        assertThat(qm.getAllProjects()).satisfiesExactly(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly(team.getName()));
    }

    @Test
    public void createProjectAsUserWithAclEnabledAndExistingTeamByNameTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userJwt = new JsonWebToken().createToken(testUser);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userJwt)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "name": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getName())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "properties": [],
                          "tags": [],
                          "isLatest":false,
                          "active": true
                        }
                        """);

        assertThat(qm.getAllProjects()).satisfiesExactly(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly(team.getName()));
    }

    @Test
    public void createProjectAsUserWithAclEnabledAndWithoutTeamTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userJwt = new JsonWebToken().createToken(testUser);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userJwt)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "properties": [],
                          "tags": [],
                          "isLatest":false,
                          "active":true
                        }
                        """);

        assertThat(qm.getAllProjects()).satisfiesExactly(project ->
                assertThat(project.getAccessTeams()).isEmpty());
    }

    @Test
    public void createProjectAsUserWithNotAllowedExistingTeamTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);

        final String userJwt = new JsonWebToken().createToken(testUser);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userJwt)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("""
                The team with UUID %s can not be assigned because it does not exist, \
                or is not accessible to the authenticated principal.""", team.getUuid());
    }

    @Test
    public void createProjectAsUserWithAclEnabledAndNotMemberOfTeamAdminTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userJwt = new JsonWebToken().createToken(testUser);

        final Team otherTeam = qm.createTeam("otherTeam", false);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userJwt)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(otherTeam.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "properties": [],
                          "tags": [],
                          "isLatest":false,
                          "active":true
                        }
                        """);

        assertThat(qm.getAllProjects()).satisfiesExactly(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly("otherTeam"));
    }

    @Test
    public void createProjectAsUserWithAclEnabledAndTeamNotExistingNoAdminTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);

        final String userJwt = new JsonWebToken().createToken(testUser);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userJwt)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "419c32eb-5a30-47d5-8a9a-fc0cda651314"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("""
                The team with UUID 419c32eb-5a30-47d5-8a9a-fc0cda651314 \
                can not be assigned because it does not exist, or is not \
                accessible to the authenticated principal.""");
    }

    @Test
    public void createProjectAsUserWithAclEnabledAndTeamNotExistingAdminTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userJwt = new JsonWebToken().createToken(testUser);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userJwt)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "419c32eb-5a30-47d5-8a9a-fc0cda651314"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("""
                The team with UUID 419c32eb-5a30-47d5-8a9a-fc0cda651314 \
                can not be assigned because it does not exist, or is not \
                accessible to the authenticated principal.""");
    }

    @Test
    public void createProjectAsApiKeyWithAclEnabledAndWithExistentTeamTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "properties": [],
                          "tags": [],
                          "isLatest":false,
                          "active":true
                        }
                        """);

        assertThat(qm.getAllProjects()).satisfiesExactly(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly(team.getName()));
    }

    @Test
    public void patchActiveProjectToInactiveTest() {
        // create project as active
        Project project = qm.createProject("ABC", null, null, null, null, null,
                null, false, false);

        // make it inactive by patch
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(/* language=JSON */ """
                        {
                          "name": "ABC-Updated",
                          "active": false
                        }
                        """));
        Assert.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "children": [],
                          "properties": [],
                          "tags": [],
                          "inactiveSince": "${json-unit.any-number}",
                          "isLatest":false,
                          "active": false
                        }
                        """);
    }

    @Test
    public void patchInactiveProjectToActiveTest() {
        // create project as inactive
        Project project = qm.createProject("ABC", null, null, null, null, null,
                new Date(), false, false);

        // make it active by patch
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(/* language=JSON */ """
                        {
                          "name": "ABC-Updated",
                          "active": true
                        }
                        """));
        Assert.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "properties": [],
                          "tags": [],
                          "isLatest":false,
                          "active": true
                        }
                        """);
    }

    @Test
    public void updateActiveProjectToInactiveTest() {
        // create project as active
        Project project = qm.createProject("ABC", null, null, null, null, null,
                null, false, false);

        // make it inactive by update
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "ABC-Updated",
                          "active": false
                        }
                        """.formatted(project.getUuid())));
        Assert.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "classifier":"APPLICATION",
                          "children": [],
                          "properties": [],
                          "tags": [],
                          "inactiveSince": "${json-unit.any-number}",
                          "isLatest":false,
                          "active": false
                        }
                        """);
    }

    @Test
    public void updateInactiveProjectToActiveTest() {
        // create project as inactive
        Project project = qm.createProject("ABC", null, null, null, null, null,
                new Date(), false, false);

        // make it active by update
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "ABC-Updated",
                          "active": true
                        }
                        """.formatted(project.getUuid())));
        Assert.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "classifier":"APPLICATION",
                          "properties": [],
                          "tags": [],
                          "isLatest":false,
                          "active": true
                        }
                        """);
    }
}
