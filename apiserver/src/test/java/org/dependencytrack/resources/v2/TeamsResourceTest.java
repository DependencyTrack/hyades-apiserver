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

import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class TeamsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TeamsResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void listTeamsShouldReturnPaginatedTeams() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        for (int i = 0; i < 2; i++) {
            qm.createTeam("team" + i);
        }

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
                      "members": 0
                    },
                    {
                      "name": "team0",
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
                  "title": "Not found",
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
                  "title": "Invalid request",
                  "detail": "The request could not be processed because it is invalid.",
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
    public void listTeamMembersShouldReturnPaginatedTeamMembers() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Team team = qm.createTeam("test");
        qm.addUserToTeam(qm.createManagedUser("foo", "password"), team);
        qm.addUserToTeam(qm.createManagedUser("bar", "password"), team);
        qm.addUserToTeam(qm.createManagedUser("baz", "password"), team);

        Response response = jersey.target("/teams/test/members")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "users": [
                    {
                      "type": "MANAGED",
                      "name": "bar"
                    },
                    {
                      "type": "MANAGED",
                      "name": "baz"
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
                  "users": [
                    {
                      "type": "MANAGED",
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
    public void listTeamMembersShouldReturnNotFoundWhenTeamDoesNotExist() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        final Response response = jersey.target("/teams/foo/members")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status": 404,
                  "title": "Not found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

}