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

import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.User;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.junit.ClassRule;
import org.junit.Test;

import java.net.URI;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class TeamsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(new ResourceConfig());

    @Test
    public void listTeamsShouldReturnPaginatedTeams() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("team0");
        qm.createTeam("team1");

        Response response = jersey.target("/teams")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "teams": [
                    {
                      "name": "Test Users",
                      "api_keys": 1,
                      "members": 0
                    },
                    {
                      "name": "team0",
                      "api_keys": 0,
                      "members": 0
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
                  "teams": [
                    {
                      "name": "team1",
                      "api_keys": 0,
                      "members": 0
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
    public void createTeamShouldCreateTeam() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createPermission(
                Permissions.VIEW_PORTFOLIO.name(),
                Permissions.VIEW_PORTFOLIO.getDescription());

        final Response response = jersey.target("/teams")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "foo",
                          "permissions": [
                            "VIEW_PORTFOLIO"
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation()).hasPath("/teams/foo");
        assertThat(getPlainTextBody(response)).isEmpty();

        qm.getPersistenceManager().evictAll();

        final Team team = qm.getTeam("foo");
        assertThat(team).isNotNull();
        assertThat(team.getPermissions()).extracting(Permission::getName).containsOnly("VIEW_PORTFOLIO");
    }

    @Test
    public void createTeamShouldReturnConflictWhenAlreadyExists() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("foo");

        final Response response = jersey.target("/teams")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "foo",
                          "permissions": [
                            "VIEW_PORTFOLIO"
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status":409,
                  "title": "Resource already exists",
                  "detail": "Team already exists"
                }
                """);

        qm.getPersistenceManager().evictAll();

        final Team team = qm.getTeam("foo");
        assertThat(team).isNotNull();
        assertThat(team.getPermissions()).isEmpty();
    }

    @Test
    public void getTeamShouldReturnTeam() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Team team = qm.createTeam("foo");
        team.setPermissions(List.of(
                qm.createPermission(
                        Permissions.VIEW_PORTFOLIO.name(),
                        Permissions.VIEW_PORTFOLIO.getDescription()),
                qm.createPermission(
                        Permissions.VIEW_VULNERABILITY.name(),
                        Permissions.VIEW_VULNERABILITY.getDescription())));

        final Response response = jersey.target("/teams/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "foo",
                  "permissions": [
                    "VIEW_PORTFOLIO",
                    "VIEW_VULNERABILITY"
                  ]
                }
                """);
    }

    @Test
    public void getTeamShouldReturnNotFoundWhenTeamDoesNotExist() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Response response = jersey.target("/teams/foo")
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
    public void deleteTeamShouldDeleteTeam() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("foo");

        final Response response = jersey.target("/teams/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        qm.getPersistenceManager().evictAll();

        assertThat(qm.getTeam("foo")).isNull();
    }

    @Test
    public void deleteTeamsShouldReturnNotFoundWhenNotExists() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Response response = jersey.target("/teams/does-not-exist")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void listTeamMembershipsShouldReturnPaginatedTeamMemberships() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Team teamA = qm.createTeam("team-a");
        qm.addUserToTeam(qm.createManagedUser("foo", "password"), teamA);
        qm.addUserToTeam(qm.createManagedUser("bar", "password"), teamA);

        final Team teamB = qm.createTeam("team-b");
        qm.addUserToTeam(qm.createManagedUser("aaa", "password"), teamB);

        Response response = jersey.target("/team-memberships")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "memberships": [
                    {
                      "team_name": "team-a",
                      "username": "bar"
                    },
                    {
                      "team_name": "team-a",
                      "username": "foo"
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
                  "memberships": [
                    {
                      "team_name": "team-b",
                      "username": "aaa"
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
    public void listTeamMembershipsShouldFilterByTeamName() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Team teamA = qm.createTeam("team-a");
        qm.addUserToTeam(qm.createManagedUser("foo", "password"), teamA);

        final Team teamB = qm.createTeam("team-b");
        qm.addUserToTeam(qm.createManagedUser("bar", "password"), teamB);

        Response response = jersey.target("/team-memberships")
                .queryParam("team", "team-b")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "memberships": [
                    {
                      "team_name": "team-b",
                      "username": "bar"
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
    public void listTeamMembershipsShouldFilterByUsername() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Team teamA = qm.createTeam("team-a");
        qm.addUserToTeam(qm.createManagedUser("foo", "password"), teamA);

        final Team teamB = qm.createTeam("team-b");
        qm.addUserToTeam(qm.createManagedUser("bar", "password"), teamB);

        final Response response = jersey.target("/team-memberships")
                .queryParam("user", "bar")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "memberships": [
                    {
                      "team_name": "team-b",
                      "username": "bar"
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
    public void createTeamMembershipShouldCreateTeamMembership() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("team-foo");
        qm.createManagedUser("user-bar", "password");

        final Response response = jersey.target("/team-memberships")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "team_name": "team-foo",
                          "username": "user-bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation()).isNull();
        assertThat(getPlainTextBody(response)).isEmpty();

        qm.getPersistenceManager().evictAll();

        assertThat(qm.getTeam("team-foo").getUsers())
                .extracting(User::getUsername)
                .contains("user-bar");
    }

    @Test
    public void createTeamMembershipShouldReturnConflictWhenAlreadyExists() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Team team = qm.createTeam("team-foo");
        final User user = qm.createManagedUser("user-bar", "password");
        qm.addUserToTeam(user, team);

        final Response response = jersey.target("/team-memberships")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "team_name": "team-foo",
                          "username": "user-bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status":409,
                  "title": "Resource already exists",
                  "detail": "Team membership already exists"
                }
                """);
    }

    @Test
    public void createTeamMembershipShouldReturnNotFoundWhenTeamNotExists() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createManagedUser("user-bar", "password");

        final Response response = jersey.target("/team-memberships")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "team_name": "team-foo",
                          "username": "user-bar"
                        }
                        """));
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
    public void createTeamMembershipShouldReturnNotFoundWhenUserNotExists() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("team-foo");

        final Response response = jersey.target("/team-memberships")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "team_name": "team-foo",
                          "username": "user-bar"
                        }
                        """));
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
    public void deleteTeamMembershipShouldDeleteTeamMembership() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Team team = qm.createTeam("foo");
        qm.addUserToTeam(qm.createManagedUser("bar", "password"), team);

        final Response response = jersey.target("/team-memberships")
                .queryParam("team", "foo")
                .queryParam("user", "bar")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();

        assertThat(team.getUsers()).isEmpty();
    }

    @Test
    public void deleteTeamMembershipShouldReturnNotFoundWhenTeamDoesNotExist() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createManagedUser("bar", "password");

        final Response response = jersey.target("/team-memberships")
                .queryParam("team", "foo")
                .queryParam("user", "bar")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
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
    public void deleteTeamMembershipShouldReturnNotFoundWhenUserDoesNotExist() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("foo");

        final Response response = jersey.target("/team-memberships")
                .queryParam("team", "foo")
                .queryParam("user", "bar")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
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
    public void deleteTeamMembershipShouldReturnNotFoundWhenMembershipDoesNotExist() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("foo");
        qm.createManagedUser("bar", "password");

        final Response response = jersey.target("/team-memberships")
                .queryParam("team", "foo")
                .queryParam("user", "bar")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
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

}