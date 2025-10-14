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

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.model.User;
import alpine.server.auth.JsonWebToken;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.IdentifiableObject;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.resources.v1.vo.ModifyUserProjectRoleRequest;
import org.glassfish.jersey.client.ClientProperties;
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

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_USER_CREATED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_USER_DELETED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_SYSTEM;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class UserResourceAuthenticatedTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(UserResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    private ManagedUser testUser;
    private String jwt;

    @Before
    @Override
    public void before() throws Exception {
        super.before();
        testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        this.jwt = new JsonWebToken().createToken(testUser);
        qm.addUserToTeam(testUser, team);
    }

     @Test
    public void getUsersTest() {
        qm.createLdapUser("testldapuser");
        qm.createOidcUser("testoidcuser");
        Response responseAll = jersey.target(V1_USER)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Response responseLdap = jersey.target(V1_USER)
                .queryParam("type", "ldap")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Response responseManaged = jersey.target(V1_USER)
                .queryParam("type", "managed")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Response responseOidc = jersey.target(V1_USER)
                .queryParam("type", "oidc")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        // add response values to a list called allResonses
        List<Integer> statuses = List.of(
            responseAll.getStatus(), responseLdap.getStatus(),
            responseManaged.getStatus(), responseOidc.getStatus()
            );
        List<Integer> expectedStatuses = List.of(200, 200, 200, 200);
        Assert.assertEquals(expectedStatuses, statuses);

        JsonArray users = parseJsonArray(responseAll);
        Assert.assertTrue(users.toArray().length >= 3);
    }

    @Test
    public void getManagedUsersTest() {
        for (int i=0; i<1000; i++) {
            qm.createManagedUser("managed-user-" + i, TEST_USER_PASSWORD_HASH);
        }
        Response response = jersey.target(V1_USER + "/managed").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1001), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1001, json.size()); // There's already a built-in managed user in ResourceTest
        Assert.assertEquals("managed-user-0", json.getJsonObject(0).getString("username"));
    }

    @Test
    public void getLdapUsersTest() {
        for (int i=0; i<1000; i++) {
            qm.createLdapUser("ldap-user-" + i);
        }
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1000, json.size());
        Assert.assertEquals("ldap-user-0", json.getJsonObject(0).getString("username"));
    }

    @Test
    public void getSelfTest() {
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("testuser", json.getString("username"));
    }

    @Test
    public void getSelfNonUserTest() {
        Response response = jersey.target(V1_USER + "/self").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    public void updateSelfTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assert.assertEquals("blackbeard@example.com", json.getString("email"));
    }

    @Test
    public void updateSelfInvalidFullnameTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("Full name is required.", body);
    }

    @Test
    public void updateSelfInvalidEmailTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("Email address is required.", body);
    }

    @Test
    public void updateSelfUnauthorizedTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        Response response = jersey.target(V1_USER + "/self").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    public void updateSelfPasswordsTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setNewPassword("newPassword");
        user.setConfirmPassword("newPassword");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assert.assertEquals("blackbeard@example.com", json.getString("email"));
    }

    @Test
    public void updateSelfPasswordMismatchTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setNewPassword("newPassword");
        user.setConfirmPassword("blah");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("Passwords do not match.", body);
    }

    @Test
    public void createLdapUserTest() throws InterruptedException {
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("blackbeard", json.getString("username"));

        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() == 1, Duration.ofSeconds(5));
        final org.dependencytrack.proto.notification.v1.Notification userNotification = deserializeValue(KafkaTopics.NOTIFICATION_USER, kafkaMockProducer.history().get(0));
        assertThat(userNotification).isNotNull();
        assertThat(userNotification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(userNotification.getGroup()).isEqualTo(GROUP_USER_CREATED);
        assertThat(userNotification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(userNotification.getTitle()).isEqualTo(NotificationConstants.Title.USER_CREATED);
        assertThat(userNotification.getContent()).isEqualTo("LDAP user created");
    }

    @Test
    public void createLdapUserInvalidUsernameTest() throws InterruptedException {
        LdapUser user = new LdapUser();
        user.setUsername("");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("Username cannot be null or blank.", body);
        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() == 0, Duration.ofSeconds(5));
    }

    @Test
    public void createLdapUserDuplicateUsernameTest() {
        qm.createLdapUser("blackbeard");
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    public void deleteLdapUserTest() throws InterruptedException {
        qm.createLdapUser("blackbeard");
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);

        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() == 1, Duration.ofSeconds(5));
        final org.dependencytrack.proto.notification.v1.Notification userNotification = deserializeValue(KafkaTopics.NOTIFICATION_USER, kafkaMockProducer.history().get(0));
        assertThat(userNotification).isNotNull();
        assertThat(userNotification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(userNotification.getGroup()).isEqualTo(GROUP_USER_DELETED);
        assertThat(userNotification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(userNotification.getTitle()).isEqualTo(NotificationConstants.Title.USER_DELETED);
        assertThat(userNotification.getContent()).isEqualTo("LDAP user deleted");
    }

    @Test
    public void createManagedUserTest() throws InterruptedException {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assert.assertEquals("blackbeard@example.com", json.getString("email"));
        Assert.assertEquals("blackbeard", json.getString("username"));

        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() == 1, Duration.ofSeconds(5));
        final org.dependencytrack.proto.notification.v1.Notification userNotification = deserializeValue(KafkaTopics.NOTIFICATION_USER, kafkaMockProducer.history().get(0));
        assertThat(userNotification).isNotNull();
        assertThat(userNotification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(userNotification.getGroup()).isEqualTo(GROUP_USER_CREATED);
        assertThat(userNotification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(userNotification.getTitle()).isEqualTo(NotificationConstants.Title.USER_CREATED);
        assertThat(userNotification.getContent()).isEqualTo("Managed user created");
    }

    @Test
    public void createManagedUserInvalidUsernameTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Username cannot be null or blank.", body);
    }

    @Test
    public void createManagedUserInvalidFullnameTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The users full name is missing.", body);
    }

    @Test
    public void createManagedUserInvalidEmailTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The users email address is missing.", body);
    }

    @Test
    public void createManagedUserInvalidPasswordTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("A password must be set.", body);
    }

    @Test
    public void createManagedUserPasswordMismatchTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("blah");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The passwords do not match.", body);
    }

    @Test
    public void createManagedUserDuplicateUsernameTest() {
        qm.createManagedUser("blackbeard", TEST_USER_PASSWORD_HASH);
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    public void updateManagedUserTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("Dr BlackBeard, Ph.D.");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Dr BlackBeard, Ph.D.", json.getString("fullname"));
        Assert.assertEquals("blackbeard@example.com", json.getString("email"));
        Assert.assertTrue(json.getBoolean("forcePasswordChange"));
        Assert.assertTrue(json.getBoolean("nonExpiryPassword"));
        Assert.assertTrue(json.getBoolean("suspended"));
    }

    @Test
    public void updateManagedUserInvalidFullnameTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The users full name is missing.", body);
    }

    @Test
    public void updateManagedUserInvalidEmailTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The users email address is missing.", body);
    }

    @Test
    public void updateManagedUserInvalidUsernameTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("");
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void deleteManagedUserTest() throws InterruptedException {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);

        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() == 1, Duration.ofSeconds(5));
        final org.dependencytrack.proto.notification.v1.Notification userNotification = deserializeValue(KafkaTopics.NOTIFICATION_USER, kafkaMockProducer.history().get(0));
        assertThat(userNotification).isNotNull();
        assertThat(userNotification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(userNotification.getGroup()).isEqualTo(GROUP_USER_DELETED);
        assertThat(userNotification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(userNotification.getTitle()).isEqualTo(NotificationConstants.Title.USER_DELETED);
        assertThat(userNotification.getContent()).isEqualTo("Managed user deleted");
    }

    @Test
    public void createOidcUserTest() throws InterruptedException {
        final OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("blackbeard", json.getString("username"));

        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() == 1, Duration.ofSeconds(5));
        final org.dependencytrack.proto.notification.v1.Notification userNotification = deserializeValue(KafkaTopics.NOTIFICATION_USER, kafkaMockProducer.history().get(0));
        assertThat(userNotification).isNotNull();
        assertThat(userNotification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(userNotification.getGroup()).isEqualTo(GROUP_USER_CREATED);
        assertThat(userNotification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(userNotification.getTitle()).isEqualTo(NotificationConstants.Title.USER_CREATED);
        assertThat(userNotification.getContent()).isEqualTo("OpenID Connect user created");
    }

    @Test
    public void createOidcUserDuplicateUsernameTest() {
        qm.createOidcUser("blackbeard");
        final OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    public void deleteOidcUserTest() {
        qm.createOidcUser("blackbeard");
        OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void addTeamToUserTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        Team team = qm.createTeam("Pirates");
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assert.assertEquals("blackbeard@example.com", json.getString("email"));
        Assert.assertFalse(json.getBoolean("forcePasswordChange"));
        Assert.assertFalse(json.getBoolean("nonExpiryPassword"));
        Assert.assertFalse(json.getBoolean("suspended"));
    }

    @Test
    public void addTeamToUserInvalidTeamTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(UUID.randomUUID().toString());
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void addTeamToUserInvalidUserTest() {
        Team team = qm.createTeam("Pirates");
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        ManagedUser user = new ManagedUser();
        user.setUsername("blah");
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void addTeamToUserDuplicateMembershipTest() {
        Team team = qm.createTeam("Pirates");
        ManagedUser user = qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        qm.addUserToTeam(user, team);
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        // TODO: Possible bug in Jersey? The response entity is set in the resource, but blank in the actual response.
        //Assert.assertEquals("The user is already a member of the specified team.", body);
    }

    @Test
    public void removeTeamFromUserTest() {
        Team team = qm.createTeam("Pirates");
        ManagedUser user = qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        qm.addUserToTeam(user, team);
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(ido, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(200, response.getStatus(), 0);
    }

    @Test
    public void setUserTeamsTest() {
        String username = qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com",
        TEST_USER_PASSWORD_HASH, false, false, false).getUsername();
        String endpoint = V1_USER + "/membership";
        List<Team> teamSet1 = List.of(
            qm.createTeam("Pirates", false),
            qm.createTeam("Penguins", false),
            qm.createTeam("Steelers", false),
            qm.createTeam("Red Sox", false),
            qm.createTeam("Cubs", false)
        );

        List<Team> teamSet2 = List.of(
            qm.createTeam("Yankees", false),
            qm.createTeam("Dodgers", false),
            qm.createTeam("Giants", false)
        );

        JsonObject teamRequest1 = Json.createObjectBuilder()
                .add("username", username)
                .add("teams", Json.createArrayBuilder(
                    teamSet1.stream().map(Team::getUuid).map(UUID::toString).toList()))
                .build();

        JsonObject teamRequest2 = Json.createObjectBuilder()
                .add("username", username)
                .add("teams", Json.createArrayBuilder(
                    teamSet2.stream().map(Team::getUuid).map(UUID::toString).toList()))
                .build();

        Response response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(teamRequest1.toString(), MediaType.APPLICATION_JSON));

        Assert.assertEquals(200, response.getStatus());

        User user = qm.getManagedUser("blackbeard");
        List<Team> userTeams = user.getTeams();

        Assert.assertEquals(userTeams.size(), teamSet1.size());
        Assert.assertTrue(userTeams.containsAll(teamSet1));

        response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(teamRequest2.toString(), MediaType.APPLICATION_JSON));

        user = qm.getUser("blackbeard");
        userTeams = user.getTeams();

        Assert.assertEquals(200, response.getStatus());
        Assert.assertEquals(userTeams.size(), teamSet2.size());
        Assert.assertTrue(Collections.disjoint(userTeams, teamSet1));
        Assert.assertTrue(userTeams.containsAll(teamSet2));
    }

    @Test
    public void setUserTeamsInvalidTest() {
        String endpoint = V1_USER + "/membership";
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com",
                TEST_USER_PASSWORD_HASH, false, false, false);
        UUID teamUuid = qm.createTeam("Pirates", false).getUuid();

        JsonObject badTeamBody = Json.createObjectBuilder()
            .add("username", "blackbeard")
            .add("teams", Json.createArrayBuilder().add(UUID.randomUUID().toString()))
            .build();

        JsonObject unknownUserBody = Json.createObjectBuilder()
            .add("username", "unknown")
            .add("teams", Json.createArrayBuilder().add(teamUuid.toString()))
            .build();
        // invalid uuid
        Response response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(badTeamBody.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus());

        // unknown user
        response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(unknownUserBody.toString(), MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus());

    }

    @Test
    public void assignProjectRoleToUserTest() {
        // Arrange
        ManagedUser user = qm.createManagedUser("roleuser", TEST_USER_PASSWORD_HASH);
        Project project = qm.createProject(
                "Test Project", "null",
                "null", Collections.emptyList(),
                null, null, null, false);

        Role role = qm.createRole("Test Role", Collections.emptyList());

        ModifyUserProjectRoleRequest request = new ModifyUserProjectRoleRequest(
                user.getUsername(),
                role.getUuid().toString(),
                project.getUuid().toString());

        // Act
        Response response = jersey.target(V1_USER + "/role").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        // Assert
        Assert.assertEquals(200, response.getStatus());
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("roleuser", json.getString("username"));
        // Optionally, check if the user has the role for the project in the DB
    }

    @Test
    public void assignProjectRoleToUserAlreadyAssignedTest() {
        ManagedUser user = qm.createManagedUser("roleuser2", TEST_USER_PASSWORD_HASH);
        Project project = qm.createProject(
                "Test Project 2","null",
                "null",Collections.emptyList(),
                null,null,null,false);
        Role role = qm.createRole("Test Role 2", Collections.emptyList());
        qm.addRoleToUser(user, role, project);


        ModifyUserProjectRoleRequest request = new ModifyUserProjectRoleRequest(
                user.getUsername(),
                role.getUuid().toString(),
                project.getUuid().toString()
        );

        Response response = jersey.target(V1_USER + "/role").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        Assert.assertEquals(304, response.getStatus());
    }

    @Test
    public void removeProjectRoleFromUserTest() {
        ManagedUser user = qm.createManagedUser("roleuser3", TEST_USER_PASSWORD_HASH);
        Project project = qm.createProject(
                "Test Project 3","null",
                "null",Collections.emptyList(),
                null,null,null,false);
        Role role = qm.createRole("Test Role 3", Collections.emptyList());
        qm.addRoleToUser(user, role, project);

        ModifyUserProjectRoleRequest request = new ModifyUserProjectRoleRequest(
                user.getUsername(),
                role.getUuid().toString(),
                project.getUuid().toString()
        );

        Response response = jersey.target(V1_USER + "/role").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method("DELETE", Entity.entity(request, MediaType.APPLICATION_JSON));

        Assert.assertEquals(204, response.getStatus());
    }

    @Test
    public void removeProjectRoleFromUserNotAssignedTest() {
        ManagedUser user = qm.createManagedUser("roleuser4", TEST_USER_PASSWORD_HASH);
        Project project = qm.createProject(
                "Test Project 4","null",
                "null",Collections.emptyList(),
                null,null,null,false);
        Role role = qm.createRole("Test Role 4", Collections.emptyList());

        ModifyUserProjectRoleRequest request = new ModifyUserProjectRoleRequest(
                user.getUsername(),
                role.getUuid().toString(),
                project.getUuid().toString()
        );

        Response response = jersey.target(V1_USER + "/role").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method("DELETE", Entity.entity(request, MediaType.APPLICATION_JSON));

        Assert.assertEquals(304, response.getStatus());
    }
}
