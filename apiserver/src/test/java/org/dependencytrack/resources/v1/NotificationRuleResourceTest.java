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
import alpine.model.Team;
import alpine.notification.NotificationLevel;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.dependencytrack.notification.publisher.PublisherClass.SendMailPublisher;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.hamcrest.Matchers.equalTo;

public class NotificationRuleResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(NotificationRuleResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    @Before
    public void before() throws Exception {
        super.before();

        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultNotificationPublishers);
    }

    @Test
    public void getAllNotificationRulesTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        qm.createNotificationRule("Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        qm.createNotificationRule("Rule 3", NotificationScope.SYSTEM, NotificationLevel.ERROR, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("Rule 1", json.getJsonObject(0).getString("name"));
        Assert.assertTrue(json.getJsonObject(0).getBoolean("enabled"));
        Assert.assertEquals("PORTFOLIO", json.getJsonObject(0).getString("scope"));
        Assert.assertEquals("INFORMATIONAL", json.getJsonObject(0).getString("notificationLevel"));
        Assert.assertEquals(0, json.getJsonObject(0).getJsonArray("notifyOn").size());
        Assert.assertTrue(UuidUtil.isValidUUID(json.getJsonObject(0).getString("uuid")));
        Assert.assertEquals("Slack", json.getJsonObject(0).getJsonObject("publisher").getString("name"));
    }

    @Test
    public void createNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = new NotificationRule();
        rule.setName("Example Rule");
        rule.setEnabled(true);
        rule.setPublisherConfig("{ \"foo\": \"bar\" }");
        rule.setMessage("A message");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setPublisher(publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertTrue(json.getBoolean("enabled"));
        Assert.assertEquals("SYSTEM", json.getString("scope"));
        Assert.assertEquals("WARNING", json.getString("notificationLevel"));
        Assert.assertEquals(0, json.getJsonArray("notifyOn").size());
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals("Slack", json.getJsonObject("publisher").getString("name"));
    }

    @Test
    public void createNotificationRuleInvalidPublisherTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setUuid(UUID.randomUUID());
        NotificationRule rule = new NotificationRule();
        rule.setName("Example Rule");
        rule.setEnabled(true);
        rule.setPublisherConfig("{ \"foo\": \"bar\" }");
        rule.setMessage("A message");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setPublisher(publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the notification publisher could not be found.", body);
    }

    @Test
    public void updateNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        rule.setNotifyOn(Collections.singleton(NotificationGroup.NEW_VULNERABILITY));
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertTrue(json.getBoolean("enabled"));
        Assert.assertEquals("PORTFOLIO", json.getString("scope"));
        Assert.assertEquals("INFORMATIONAL", json.getString("notificationLevel"));
        Assert.assertEquals("NEW_VULNERABILITY", json.getJsonArray("notifyOn").getString(0));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals("Slack", json.getJsonObject("publisher").getString("name"));
    }

    @Test
    public void updateNotificationRuleInvalidTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule = qm.detach(NotificationRule.class, rule.getId());
        rule.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the notification rule could not be found.", body);
    }

    @Test
    public void deleteNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(rule, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void addProjectToRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("projects").size());
        Assert.assertEquals("Acme Example", json.getJsonArray("projects").getJsonObject(0).getString("name"));
        Assert.assertEquals(project.getUuid().toString(), json.getJsonArray("projects").getJsonObject(0).getString("uuid"));
    }

    @Test
    public void addProjectToRuleInvalidRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    public void addProjectToRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    public void addProjectToRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void addProjectToRuleDuplicateProjectTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addProjectToRuleAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final NotificationPublisher publisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createNotificationRule(
                "rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void removeProjectFromRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeProjectFromRuleInvalidRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    public void removeProjectFromRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    public void removeProjectFromRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void removeProjectFromRuleDuplicateProjectTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeProjectFromRuleAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final NotificationPublisher publisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createNotificationRule(
                "rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(project));

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void addTeamToRuleTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("teams").size());
        Assert.assertEquals("Team Example", json.getJsonArray("teams").getJsonObject(0).getString("name"));
        Assert.assertEquals(team.getUuid().toString(), json.getJsonArray("teams").getJsonObject(0).getString("uuid"));
    }

    @Test
    public void addTeamToRuleInvalidRuleTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    public void addTeamToRuleInvalidTeamTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }


    @Test
    public void addTeamToRuleDuplicateTeamTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<Team> teams = new HashSet<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addTeamToRuleInvalidPublisherTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Team subscriptions are only possible on notification rules with EMAIL publisher.", body);
    }

    @Test
    public void addTeamToRuleWithCustomEmailPublisherTest() {
        final Team team = qm.createTeam("Team Example");
        final NotificationPublisher publisher = qm.createNotificationPublisher("foo", "description", SendMailPublisher.name(), "template", "templateMimeType", false);
        final NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        final Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + team.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publisherUuid", equalTo(publisher.getUuid().toString()))
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .withMatcher("teamUuid", equalTo(team.getUuid().toString()))
                .isEqualTo("""
                        {
                          "name": "Example Rule",
                          "enabled": true,
                          "notifyChildren": true,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "projects": [],
                          "tags": [],
                          "teams": [
                            {
                              "uuid": "${json-unit.matches:teamUuid}",
                              "name": "Team Example",
                              "permissions": []
                            }
                          ],
                          "notifyOn": [],
                          "publisher": {
                            "name": "foo",
                            "description": "description",
                            "publisherClass": "SendMailPublisher",
                            "templateMimeType": "templateMimeType",
                            "defaultPublisher": false,
                            "uuid": "${json-unit.matches:publisherUuid}"
                          },
                          "uuid": "${json-unit.matches:ruleUuid}"
                        }
                        """);
    }

    @Test
    public void removeTeamFromRuleTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<Team> teams = new HashSet<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeTeamFromRuleInvalidRuleTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    public void removeTeamFromRuleInvalidTeamTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void removeTeamFromRuleDuplicateTeamTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeTeamToRuleInvalidPublisherTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Team subscriptions are only possible on notification rules with EMAIL publisher.", body);
    }

    @Test
    public void updateNotificationRuleWithTagsTest() {
        final NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        // Tag the rule with "foo" and "bar".
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "tags": [
                            {
                              "name": "foo"
                            },
                            {
                              "name": "bar"
                            }
                          ]
                        }
                        """.formatted(rule.getUuid()), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "enabled": false,
                          "notifyChildren": false,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "projects": [],
                          "tags": [
                            {
                              "name": "foo"
                            },
                            {
                              "name": "bar"
                            }
                          ],
                          "teams": [],
                          "notifyOn": [],
                          "publisher": {
                            "name": "${json-unit.any-string}",
                            "description": "${json-unit.any-string}",
                            "publisherClass": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          "uuid": "${json-unit.matches:ruleUuid}"
                        }
                        """);

        // Replace the previous tags with only "baz".
        response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "tags": [
                            {
                              "name": "baz"
                            }
                          ]
                        }
                        """.formatted(rule.getUuid()), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "enabled": false,
                          "notifyChildren": false,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "projects": [],
                          "tags": [
                            {
                              "name": "baz"
                            }
                          ],
                          "teams": [],
                          "notifyOn": [],
                          "publisher": {
                            "name": "${json-unit.any-string}",
                            "description": "${json-unit.any-string}",
                            "publisherClass": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          "uuid": "${json-unit.matches:ruleUuid}"
                        }
                        """);
    }
}
