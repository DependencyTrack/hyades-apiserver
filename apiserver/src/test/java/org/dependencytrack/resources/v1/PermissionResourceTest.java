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
import alpine.model.Permission;
import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Role;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class PermissionResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(PermissionResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    @Before
    public void before() throws Exception {
        super.before();
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultPermissions();
    }

    @Test
    public void getAllPermissionsTest() {
        Response response = jersey.target(V1_PERMISSION).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(38, json.size());
        Assert.assertEquals("ACCESS_MANAGEMENT", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("Allows the management of users, teams, and API keys", json.getJsonObject(0).getString("description"));
    }

    @Test
    public void addPermissionToUserTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("user1", json.getString("username"));
        Assert.assertEquals(1, json.getJsonArray("permissions").size());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", json.getJsonArray("permissions").getJsonObject(0).getString("name"));
    }

    @Test
    public void addPermissionToUserInvalidUserTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void addPermissionToUserInvalidPermissionTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToUserDuplicateTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromUserTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("user1", json.getString("username"));
        Assert.assertEquals(0, json.getJsonArray("permissions").size());
    }

    @Test
    public void removePermissionFromUserInvalidUserTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void removePermissionFromUserInvalidPermissionTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromUserNoChangesTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Response response = jersey.target(V1_PERMISSION + "/BOM_UPLOAD/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addPermissionToTeamTest() {
        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("team1", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("permissions").size());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", json.getJsonArray("permissions").getJsonObject(0).getString("name"));
    }

    @Test
    public void addPermissionToTeamInvalidTeamTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void addPermissionToTeamInvalidPermissionTest() {
        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToTeamDuplicateTest() {
        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        team.getPermissions().add(permission);
        qm.persist(team);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromTeamTest() {
        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        team.getPermissions().add(permission);
        qm.persist(team);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("team1", json.getString("name"));
        Assert.assertEquals(0, json.getJsonArray("permissions").size());
    }

    @Test
    public void removePermissionFromTeamInvalidTeamTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void removePermissionFromTeamInvalidPermissionTest() {
        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromTeamNoChangesTest() {
        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        Response response = jersey.target(V1_PERMISSION + "/BOM_UPLOAD/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void setUserPermissionsTest() {
        String username = qm.createManagedUser("user2", TEST_USER_PASSWORD_HASH).getUsername();
        String endpoint = V1_PERMISSION + "/user";

        List<Permission> permissionSet1 = List.of(
                qm.getPermission("ACCESS_MANAGEMENT"),
                qm.getPermission("ACCESS_MANAGEMENT_CREATE"),
                qm.getPermission("ACCESS_MANAGEMENT_DELETE"));

        List<Permission> permissionSet2 = List.of(
                qm.getPermission("BOM_UPLOAD"),
                qm.getPermission("VIEW_PORTFOLIO"),
                qm.getPermission("PORTFOLIO_MANAGEMENT"),
                qm.getPermission("PORTFOLIO_MANAGEMENT_CREATE"));

        JsonObject permissionRequest1 = Json.createObjectBuilder()
                .add("username", username)
                .add("permissions", Json.createArrayBuilder(permissionSet1.stream().map(Permission::getName).toList()))
                .build();

        JsonObject permissionRequest2 = Json.createObjectBuilder()
                .add("username", username)
                .add("permissions", Json.createArrayBuilder(permissionSet2.stream().map(Permission::getName).toList()))
                .build();

        // Test initial assignment.
        Response response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequest1.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus());

        JsonObject jsonResponse = parseJsonObject(response);

        Assert.assertNotNull("JSON response should not be null", jsonResponse);
        Assert.assertEquals(permissionSet1.size(), jsonResponse.getJsonArray("permissions").size());

        ManagedUser user = qm.getManagedUser(username);
        List<Permission> userPermissions = user.getPermissions();

        Assert.assertEquals("User should have 3 permissions assigned", userPermissions.size(), 3);
        Assert.assertTrue("User should have all permissions assigned: " + userPermissions,
                userPermissions.equals(permissionSet1));

        // Test replacement.
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequest2.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus());

        // Refresh
        user = qm.getManagedUser(username);
        userPermissions = user.getPermissions();

        Assert.assertTrue("User should not have any of the old permissions assigned",
                Collections.disjoint(userPermissions, permissionSet1));
        Assert.assertTrue("User should have all new permissions assigned: " + userPermissions,
                userPermissions.containsAll(permissionSet2));

    }

    @Test
    public void setUserPermissionsInvalidTest() {
        qm.createManagedUser("user2", TEST_USER_PASSWORD_HASH);

        // Create a raw JSON payload with invalid permissions.
        JsonObject requestBody = Json.createObjectBuilder()
                .add("username", "user2")
                .add("permissions", Json.createArrayBuilder()
                        .add("Invalid")
                        .add("Permission")
                        .add("List")
                        .add("Four"))
                .build();

        Response response = jersey.target(V1_PERMISSION + "/user")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(requestBody.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus());

        JsonObject jsonResponse = parseJsonObject(response);
        String detail = jsonResponse.get("detail").toString();
        Assert.assertNotNull(jsonResponse);

        List<String> allPerms = qm.getPermissions().stream()
                .map(Permission::getName)
                .toList();

        // Verify that the request was parsed correctly but contained invalid permissions.
        Assert.assertTrue(allPerms.stream().allMatch(perm -> detail.contains(perm)));
    }

    @Test
    public void setTeamPermissionsTest() {
        UUID teamUuid = qm.createTeam("team1").getUuid();
        String endpoint = V1_PERMISSION + "/team";

        List<Permission> permissionSet1 = List.of(
                qm.getPermission("ACCESS_MANAGEMENT"),
                qm.getPermission("ACCESS_MANAGEMENT_CREATE"),
                qm.getPermission("ACCESS_MANAGEMENT_DELETE"));

        List<Permission> permissionSet2 = List.of(
                qm.getPermission("BOM_UPLOAD"),
                qm.getPermission("VIEW_PORTFOLIO"),
                qm.getPermission("PORTFOLIO_MANAGEMENT"),
                qm.getPermission("PORTFOLIO_MANAGEMENT_CREATE"));

        JsonObject permissionRequet1 = Json.createObjectBuilder()
                .add("team", teamUuid.toString())
                .add("permissions", Json.createArrayBuilder(permissionSet1.stream().map(Permission::getName).toList()))
                .build();

        JsonObject permissionRequet2 = Json.createObjectBuilder()
                .add("team", teamUuid.toString())
                .add("permissions", Json.createArrayBuilder(permissionSet2.stream().map(Permission::getName).toList()))
                .build();

        // Test initial assignment.
        Response response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequet1.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus());

        JsonObject jsonResponse = parseJsonObject(response);

        Assert.assertNotNull("JSON response should not be null", jsonResponse);
        Assert.assertEquals(permissionSet1.size(), jsonResponse.getJsonArray("permissions").size());

        Team team = qm.getObjectByUuid(Team.class, teamUuid);
        List<Permission> userPermissions = team.getPermissions();

        Assert.assertEquals("User should have 3 permissions assigned", userPermissions.size(), 3);
        Assert.assertTrue("User should have all permissions assigned: " + userPermissions,
                userPermissions.equals(permissionSet1));

        // Test replacement.
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequet2.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus());

        // Refresh.
        team = qm.getObjectByUuid(Team.class, teamUuid);
        userPermissions = team.getPermissions();

        Assert.assertTrue("User should not have any of the old permissions assigned",
                Collections.disjoint(userPermissions, permissionSet1));
        Assert.assertTrue("User should have all new permissions assigned: " + userPermissions,
                userPermissions.containsAll(permissionSet2));
    }

    @Test
    public void addPermissionToRoleTest() {
        Role role = qm.createRole("Test Role", new ArrayList<Permission>());

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/role/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));

        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Test Role", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("permissions").size());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT",
                json.getJsonArray("permissions").getJsonObject(0).getString("name"));
    }

    @Test
    public void addPermissionToRoleInvalidRoleTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/role/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));

        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The role could not be found.", body);
    }

    @Test
    public void addPermissionToRoleInvalidPermissionTest() {
        Role role = qm.createRole("Test Role", new ArrayList<Permission>());

        Response response = jersey.target(V1_PERMISSION + "/BLAH/role/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));

        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToRoleDuplicateTest() {
        List<Permission> permissionSet1 = List.of(
                qm.getPermission("PORTFOLIO_MANAGEMENT"));
        Role role = qm.createRole("Test Role", permissionSet1);

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/role/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));

        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromRoleTest() {
        List<Permission> permissionSet1 = List.of(
                qm.getPermission("PORTFOLIO_MANAGEMENT"));
        Role role = qm.createRole("Test Role", permissionSet1);

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/role/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();

        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Test Role", json.getString("name"));
        Assert.assertEquals(0, json.getJsonArray("permissions").size());
    }

    @Test
    public void removePermissionFromRoleInvalidRoleTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/role/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .delete();

        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The role could not be found.", body);
    }

    @Test
    public void removePermissionFromRoleInvalidPermissionTest() {
        Role role = qm.createRole("Test Role", new ArrayList<Permission>());

        Response response = jersey.target(V1_PERMISSION + "/BLAH/role/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();

        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromRoleNoChangesTest() {
        Role role = qm.createRole("Test Role", new ArrayList<Permission>());

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/role/" + role.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();

        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void setRolePermissionsTest() {
        // Arrange: create a role and permissions
        Role role = qm.createRole("testRole", Collections.emptyList());
        String roleUuid = role.getUuid().toString();

        List<Permission> permissionSet1 = List.of(
                qm.getPermission("ACCESS_MANAGEMENT"),
                qm.getPermission("ACCESS_MANAGEMENT_CREATE"),
                qm.getPermission("ACCESS_MANAGEMENT_DELETE"));

        List<Permission> permissionSet2 = List.of(
                qm.getPermission("BOM_UPLOAD"),
                qm.getPermission("VIEW_PORTFOLIO"),
                qm.getPermission("PORTFOLIO_MANAGEMENT"));

        JsonObject request1 = Json.createObjectBuilder()
                .add("role", roleUuid)
                .add("permissions", Json.createArrayBuilder(permissionSet1.stream().map(Permission::getName).toList()))
                .build();

        JsonObject request2 = Json.createObjectBuilder()
                .add("role", roleUuid)
                .add("permissions", Json.createArrayBuilder(permissionSet2.stream().map(Permission::getName).toList()))
                .build();

        String endpoint = V1_PERMISSION + "/role";

        // Act & Assert: assign first set
        Response response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request1.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus());
        Role updatedRole = qm.getObjectByUuid(Role.class, role.getUuid());
        Assert.assertTrue(updatedRole.getPermissions().containsAll(permissionSet1));

        // Assign second set (replace)
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request2.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus());
        updatedRole = qm.getObjectByUuid(Role.class, role.getUuid());
        Assert.assertTrue(updatedRole.getPermissions().containsAll(permissionSet2));
        Assert.assertTrue(updatedRole.getPermissions().stream().noneMatch(p -> permissionSet1.contains(p)));

        // Assign same set again (should return 304)
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request2.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(304, response.getStatus());

        // Invalid role UUID
        JsonObject invalidRoleRequest = Json.createObjectBuilder()
                .add("role", UUID.randomUUID().toString())
                .add("permissions", Json.createArrayBuilder(permissionSet1.stream().map(Permission::getName).toList()))
                .build();
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(invalidRoleRequest.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus());

        // Invalid permissions
        JsonObject invalidPermRequest = Json.createObjectBuilder()
                .add("role", roleUuid)
                .add("permissions", Json.createArrayBuilder().add("INVALID_PERMISSION"))
                .build();
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(invalidPermRequest.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus());
    }

}
