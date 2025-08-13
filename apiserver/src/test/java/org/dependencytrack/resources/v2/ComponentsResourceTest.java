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
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.junit.ClassRule;
import org.junit.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class ComponentsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(new ResourceConfig());

    @Test
    public void createComponentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        Project project = qm.createProject("acme", null, null, null, null, null, null, false);

        final Response response = jersey.target("/components")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project_uuid": "%s",
                          "name": "foo",
                          "purl": "pkg:maven/org.acme/abc",
                          "hashes": {
                            "sha1": "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
                            "sha3_512": "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7"
                          },
                          "supplier": {
                            "name": "supplier",
                            "contacts": [
                                {
                                  "name": "author"
                                }
                            ]
                          }
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation()).hasPath("/components/project/" + project.getUuid());
        assertThat(getPlainTextBody(response)).isEmpty();

        qm.getPersistenceManager().evictAll();

        final var componentsPage = qm.getComponents(project, false, false, false);
        assertThatJson(componentsPage).isEqualTo("""
                {
                  "total" : 1,
                  "objects" : [ {
                    "authors" : [ ],
                    "name" : "foo",
                    "sha1" : "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
                    "sha3_512" : "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7",
                    "purl" : "pkg:maven/org.acme/abc",
                    "purlCoordinates" : "pkg:maven/org.acme/abc",
                    "project" : {
                      "name" : "acme",
                      "uuid" : "${json-unit.any-string}",
                      "isLatest" : false,
                      "active" : true
                    },
                    "uuid" : "${json-unit.any-string}",
                    "componentMetaInformation" : {
                      "lastFetched" : "${json-unit.any-number}"
                    },
                    "expandDependencyGraph" : false,
                    "occurrenceCount" : 0,
                    "isInternal" : false
                  } ]
                }
                """);
    }

    @Test
    public void createComponentAclTest() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        Project project = qm.createProject("acme", null, null, null, null, null, null, false);

        Response response = jersey.target("/components")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project_uuid": "%s",
                          "name": "foo"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(401);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                     "title" : "Unauthorized",
                     "detail" : "Not authorized to access the requested resource.",
                     "type" : "about:blank",
                     "status" : 401
                }
                """);

        project.addAccessTeam(team);
        response = jersey.target("/components")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project_uuid": "%s",
                          "name": "foo"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
    }
}