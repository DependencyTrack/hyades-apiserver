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
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import java.net.URI;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class ProjectsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(new ResourceConfig());

    @Test
    public void listProjectComponents() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        var project = prepareProject();

        Response response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "components" : [ {
                        "name" : "component-name",
                        "version" : "3.0",
                        "group" : "component-group",
                        "purl" : "pkg:maven/foo/bar@3.0",
                        "internal" : false,
                        "occurrence_count" : 0,
                        "uuid" : "${json-unit.any-string}"
                      }, {
                        "name" : "component-name",
                        "version" : "2.0",
                        "group" : "component-group",
                        "purl" : "pkg:maven/foo/bar@2.0",
                        "internal" : false,
                        "resolved_license" : {
                              "name" : "MIT License",
                              "license_id" : "MIT",
                              "uuid" : "${json-unit.any-string}",
                              "osi_approved" : false,
                              "fsf_libre" : false,
                              "custom_license" : false
                        },
                        "occurrence_count" : 0,
                        "uuid" : "${json-unit.any-string}"
                      }
                  ],
                  "_pagination": {
                      "links": {
                        "self": "${json-unit.any-string}",
                        "next": "${json-unit.any-string}"
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
                  "components" : [ {
                       "name" : "component-name",
                       "version" : "1.0",
                       "group" : "component-group",
                       "purl" : "pkg:maven/foo/bar@1.0",
                       "internal" : false,
                       "occurrence_count" : 0,
                       "hashes": {
                            "md5": "hash-md5"
                       },
                       "uuid" : "${json-unit.any-string}"
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
    public void listProjectComponentsWithAclEnabledTest() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        // Create project and give access to current principal's team.
        final Project accessProject = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        accessProject.addAccessTeam(team);

        // Create a second project that the current principal has no access to.
        final Project noAccessProject = qm.createProject("acme-app-b", null, "2.0.0", null, null, null, null, false);

        Response response = jersey.target("/projects/" + accessProject.getUuid() + "/components")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assert.assertEquals(200, response.getStatus(), 0);

        response = jersey.target("/projects/" + noAccessProject.getUuid() + "/components")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assert.assertEquals(403, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "title" : "Project access denied",
                  "detail" : "Access to the requested project is forbidden",
                  "type" : "about:blank",
                  "status" : 403
                }
                """);
    }

    @Test
    public void listComponentsForProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Response response = jersey.target("/projects/" + UUID.randomUUID() + "/components")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assert.assertEquals(404, response.getStatus(), 0);
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
    public void cloneProjectShouldReturnUuidOfClonedProject() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).containsOnlyKeys("uuid");

        final String clonedProjectUuid = responseJson.getString("uuid");
        assertThat(response.getLocation()).isNotNull();
        assertThat(response.getLocation().getPath()).endsWith("/projects/" + clonedProjectUuid);

        final Project clonedProject = qm.getObjectByUuid(Project.class, clonedProjectUuid);
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.getName()).isEqualTo("acme-app");
        assertThat(clonedProject.getVersion()).isEqualTo("2.0.0");
    }

    @Test
    public void cloneProjectShouldMarkNewProjectAsLatestWhenRequested() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setIsLatest(true);
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0",
                          "version_is_latest": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).containsOnlyKeys("uuid");

        final String clonedProjectUuid = responseJson.getString("uuid");
        assertThat(response.getLocation()).isNotNull();
        assertThat(response.getLocation().getPath()).endsWith("/projects/" + clonedProjectUuid);

        final Project clonedProject = qm.getObjectByUuid(Project.class, clonedProjectUuid);
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.getName()).isEqualTo("acme-app");
        assertThat(clonedProject.getVersion()).isEqualTo("2.0.0");
        assertThat(clonedProject.isLatest()).isTrue();

        qm.getPersistenceManager().evictAll(project);
        assertThat(project.isLatest()).isFalse();
    }

    @Test
    public void cloneProjectShouldReturnForbiddenWhenAclIsEnabledAndProjectIsNotAccessible() {
        enablePortfolioAccessControl();

        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);
    }

    @Test
    public void cloneProjectShouldReturnNotFoundWhenProjectDoesNotExist() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final Response response = jersey.target("/projects/c5b13f13-f2f0-4a30-97b5-94d164a345f6/clone")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project could not be found"
                }
                """);
    }

    @Test
    public void cloneProjectShouldReturnConflictWhenNewVersionAlreadyExists() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "1.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 409,
                  "title": "Resource already exists",
                  "detail": "Target project version already exists: 1.0.0"
                }
                """);
    }

    private Project prepareProject() {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final var license = new License();
        license.setLicenseId("MIT");
        license.setName("MIT License");
        qm.persist(license);

        Component component = new Component();
        component.setProject(project);
        component.setGroup("component-group");
        component.setName("component-name");
        component.setVersion("1.0");
        component.setPurl("pkg:maven/foo/bar@1.0");
        component.setMd5("hash-md5");
        qm.createComponent(component, false);

        component = new Component();
        component.setProject(project);
        component.setGroup("component-group");
        component.setName("component-name");
        component.setVersion("2.0");
        component.setPurl("pkg:maven/foo/bar@2.0");
        component.setResolvedLicense(license);
        qm.createComponent(component, false);

        component = new Component();
        component.setProject(project);
        component.setGroup("component-group");
        component.setName("component-name");
        component.setVersion("3.0");
        component.setPurl("pkg:maven/foo/bar@3.0");
        qm.createComponent(component, false);

        return project;
    }
}