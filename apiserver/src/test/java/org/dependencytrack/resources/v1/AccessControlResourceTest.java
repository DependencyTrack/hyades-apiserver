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

import alpine.model.ManagedUser;
import alpine.model.Team;
import alpine.server.auth.PasswordService;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class AccessControlResourceTest extends ResourceTest {

    protected static final String TEST_PASSWORD_HASH = new String(
            PasswordService.createHash("testuser".toCharArray()));

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(AccessControlResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void addMappingTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_ACL + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "team": "%s"
                        }
                        """.formatted(project.getUuid(), super.team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getAccessTeams()).satisfiesExactly(team -> {
            assertThat(team.getId()).isEqualTo(super.team.getId());
        });
    }

    @Test
    public void addMappingTeamNotFoundTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_ACL + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "team": "d1cb8b28-8345-43f0-a041-e671290817d0"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Team could not be found"
                }
                """);
    }

    @Test
    public void addMappingProjectNotFoundTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Response response = jersey.target(V1_ACL + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "d1cb8b28-8345-43f0-a041-e671290817d0",
                          "team": "%s"
                        }
                        """.formatted(super.team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project could not be found"
                }
                """);
    }

    @Test
    public void addMappingConflictTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.addAccessTeam(super.team);
        qm.persist(project);

        final Response response = jersey.target(V1_ACL + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "team": "%s"
                        }
                        """.formatted(project.getUuid(), super.team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 409,
                  "title": "Conflict",
                  "detail": "A mapping with the same team and project already exists"
                }
                """);
    }

    @Test
    public void deleteMappingTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final var otherTeam = new Team();
        otherTeam.setName("other-team");
        qm.persist(otherTeam);

        final var project = new Project();
        project.setName("acme-app");
        project.addAccessTeam(super.team);
        project.addAccessTeam(otherTeam);
        qm.persist(project);

        final Response response = jersey
                .target(V1_ACL + "/mapping/team/" + otherTeam.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().evictAll();

        assertThat(project.getAccessTeams())
                .satisfiesExactly(team -> assertThat(team.getId()).isEqualTo(super.team.getId()));
    }

    @Test
    public void deleteMappingTeamNotFoundTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.addAccessTeam(super.team);
        qm.persist(project);

        final Response response = jersey
                .target(V1_ACL + "/mapping/team/c4e2c34b-38c5-4b47-991f-b207ff71bfeb/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Team could not be found"
                }
                """);
    }

    @Test
    public void deleteMappingProjectNotFoundTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.addAccessTeam(super.team);
        qm.persist(project);

        final Response response = jersey
                .target(V1_ACL + "/mapping/team/" + super.team.getUuid()
                        + "/project/c4e2c34b-38c5-4b47-991f-b207ff71bfeb")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project could not be found"
                }
                """);
    }

    @Test
    public void retrieveProjectsByTeamTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        var localTeam = new Team();
        localTeam.setName("test-team");
        qm.persist(localTeam);

        final var project = new Project();
        project.setName("acme-app");
        project.addAccessTeam(super.team);
        qm.persist(project);

        // No projects assigned to local team
        Response response = jersey.target(V1_ACL + "/team/" + localTeam.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        Assert.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));

        // One project assigned to super team
        response = jersey.target(V1_ACL + "/team/" + super.team.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void retrieveUserProjectsTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);

        final var project1 = new Project();
        project1.setName("Project 1");
        qm.persist(project1);

        final var project2 = new Project();
        project2.setName("Project 2");
        qm.persist(project2);

        final ManagedUser user = qm.createManagedUser("user", TEST_PASSWORD_HASH);

        final Response response = jersey.target(V1_ACL + "/user/" + user.getUsername())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaders().get(TOTAL_COUNT_HEADER)).isNotNull();
        assertThat(response.getHeaders().get(TOTAL_COUNT_HEADER).get(0)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isArray().extracting("name").containsExactly("Project 1",
                "Project 2");
    }

    @Test
    public void retrieveUserProjectsNoContentTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);

        final ManagedUser user = qm.createManagedUser("user", TEST_PASSWORD_HASH);

        final Response response = jersey.target(V1_ACL + "/user/" + user.getUsername())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaders().get(TOTAL_COUNT_HEADER)).isNotNull();
        assertThat(response.getHeaders().get(TOTAL_COUNT_HEADER).get(0)).isEqualTo("0");
    }
}
