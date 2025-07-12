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
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
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
    public void createTeamsShouldCreateMultipleTeams() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("foo");
        qm.createPermission(
                Permissions.VIEW_PORTFOLIO.name(),
                Permissions.VIEW_PORTFOLIO.getDescription());

        final Response response = jersey.target("/teams")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "teams": [
                            {
                              "id": "bulk-item-1",
                              "name": "foo",
                              "permissions": [
                                "VIEW_PORTFOLIO"
                              ]
                            },
                            {
                              "id": "bulk-item-2",
                              "name": "bar",
                              "permissions": [
                                "DOES_NOT_EXIST",
                                "VIEW_PORTFOLIO"
                              ]
                            },
                            {
                              "id": "bulk-item-3",
                              "name": "baz"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(207);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "teams": [
                            {
                              "id": "bulk-item-1",
                              "status": "ALREADY_EXISTS"
                            },
                            {
                              "id": "bulk-item-2",
                              "status": "CREATED"
                            },
                            {
                              "id": "bulk-item-3",
                              "status": "CREATED"
                            }
                          ]
                        }
                        """);

        qm.getPersistenceManager().evictAll();

        final Team teamFoo = qm.getTeam("foo");
        assertThat(teamFoo).isNotNull();
        assertThat(teamFoo.getPermissions()).isEmpty();

        final Team teamBar = qm.getTeam("bar");
        assertThat(teamBar).isNotNull();
        assertThat(teamBar.getPermissions()).extracting(Permission::getName).containsOnly("VIEW_PORTFOLIO");

        final Team teamBaz = qm.getTeam("baz");
        assertThat(teamBaz).isNotNull();
        assertThat(teamBaz.getPermissions()).isEmpty();
    }

    @Test
    public void createTeamsShouldReturnBadRequestForNonUniqueBulkRequestItemIds() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Response response = jersey.target("/teams")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "teams": [
                            {
                              "id": "bulk-item-1",
                              "name": "foo"
                            },
                            {
                              "id": "bulk-item-1",
                              "name": "bar"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Bulk request item IDs are not unique."
                }
                """);
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
    public void deleteTeamsShouldDeleteMultipleTeams() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        for (int i = 0; i < 5; i++) {
            qm.createTeam("team" + i);
        }

        final Response response = jersey.target("/teams")
                .queryParam("names", "team0", "team1", "team666")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(207);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "teams": [
                            {
                              "name": "team0",
                              "status": "DELETED"
                            },
                            {
                              "name": "team1",
                              "status": "DELETED"
                            },
                            {
                              "name": "team666",
                              "status": "DOES_NOT_EXIST"
                            }
                          ]
                        }
                        """);
        assertThat(qm.getTeams().getList(Team.class)).satisfiesExactlyInAnyOrder(
                team -> assertThat(team.getName()).isEqualTo("team2"),
                team -> assertThat(team.getName()).isEqualTo("team3"),
                team -> assertThat(team.getName()).isEqualTo("team4"),
                team -> assertThat(team.getName()).isEqualTo("Test Users"));
    }

    @Test
    public void deleteTeamsShouldReturnBadRequestWhenNoNamesProvided() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Response response = jersey.target("/teams")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "The request could not be processed because it failed validation.",
                  "errors": [
                    {
                      "path": "deleteTeams.names",
                      "value": "[]",
                      "message": "size must be between 1 and 100"
                    }
                  ]
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
    public void createTeamMembershipsShouldCreateTeamMemberships() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        qm.createTeam("team-a");
        final Team teamB = qm.createTeam("team-b");
        final User userA = qm.createManagedUser("user-a", "password");
        qm.addUserToTeam(userA, teamB);

        final Response response = jersey.target("/team-memberships")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "memberships": [
                            {
                              "id": "bulk-item-1",
                              "team_name": "team-a",
                              "username": "user-a"
                            },
                            {
                              "id": "bulk-item-2",
                              "team_name": "does-not-exist",
                              "username": "user-a"
                            },
                            {
                              "id": "bulk-item-3",
                              "team_name": "team-a",
                              "username": "does-not-exist"
                            },
                            {
                              "id": "bulk-item-4",
                              "team_name": "team-b",
                              "username": "user-a"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(207);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "memberships": [
                            {
                              "id": "bulk-item-1",
                              "status": "CREATED"
                            },
                            {
                              "id": "bulk-item-2",
                              "status": "TEAM_DOES_NOT_EXIST"
                            },
                            {
                              "id": "bulk-item-3",
                              "status": "USER_DOES_NOT_EXIST"
                            },
                            {
                              "id": "bulk-item-4",
                              "status": "ALREADY_EXISTS"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void createTeamMembershipsShouldReturnBadRequestForNonUniqueBulkRequestItemIds() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Response response = jersey.target("/team-memberships")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "memberships": [
                            {
                              "id": "bulk-item-1",
                              "team_name": "team-a",
                              "username": "user-a"
                            },
                            {
                              "id": "bulk-item-1",
                              "team_name": "team-b",
                              "username": "user-b"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Bulk request item IDs are not unique."
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