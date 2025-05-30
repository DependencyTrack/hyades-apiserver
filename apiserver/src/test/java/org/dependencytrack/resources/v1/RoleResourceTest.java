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

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import alpine.common.util.UuidUtil;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class RoleResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(RoleResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Before
    @Override
    public void before() throws Exception {
        super.before();
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultRoles();
    }

    @Test
    public void getRolesTest() {
        Response response = jersey.target(V1_ROLE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(4, json.size());
        for (int i = 0; i < json.size(); i++) {
            Assert.assertNotNull(json.getJsonObject(i).getString("name"));
            Assert.assertNotNull(json.getJsonObject(i).getString("uuid"));
        }
    }

    @Test
    public void getRoleTest() {
        List<Permission> rolePermissions = new ArrayList<Permission>();
        Role role = qm.createRole("ABC", rolePermissions);
        Response response = jersey.target(V1_ROLE + "/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
    }

    @Test
    public void getRoleByInvalidUuidTest() {
        Response response = jersey.target(V1_ROLE + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The role could not be found.", body);
    }

    @Test
    public void createRoleTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        Response response = jersey.target(V1_ROLE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "ABC",
                          "permissions": []
                        }
                        """));
        Assert.assertEquals(201, response.getStatus());
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    public void updateRoleTest() {
        List<Permission> rolePermissions = new ArrayList<Permission>();
        Role role = qm.createRole("My Role", rolePermissions);
        role.setName("My New Role Name");
        Response response = jersey.target(V1_ROLE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(role, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My New Role Name", json.getString("name"));
    }

    @Test
    public void deleteRoleTest() {
        List<Permission> rolePermissions = new ArrayList<Permission>();
        Role role = qm.createRole("My Role", rolePermissions);
        Response response = jersey.target(V1_ROLE + "/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(role, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void getUserRolesTest() throws ParseException {
        final var testProject = new Project();
        testProject.setId(1);
        testProject.setName("test-project");
        testProject.setVersion("1.0.0");
        qm.persist(testProject);

        final var testUser = new ManagedUser();
        testUser.setFullname("test user created for testing");
        testUser.setId(1);
        testUser.setUsername("test-user");
        DateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
        testUser.setLastPasswordChange(dateFormatter.parse("20250324"));
        testUser.setPassword(TEST_USER_PASSWORD_HASH);
        qm.persist(testUser);

        final var expectedRole = new Role();
        expectedRole.setId(1);
        expectedRole.setName("maintainer");
        qm.persist(expectedRole);

        qm.addRoleToUser(testUser, expectedRole, testProject);

        Response response = jersey.target(V1_ROLE + "/test-user/role").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1, json.size());
        Assert.assertEquals("maintainer", json.getJsonObject(0).getJsonObject("role").getString("name"));
    }

}
