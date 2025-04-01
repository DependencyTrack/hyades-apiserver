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
package org.dependencytrack.model;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class NotificationRuleTest {

    @Test
    public void testId() {
        NotificationRule rule = new NotificationRule();
        rule.setId(111);
        Assert.assertEquals(111L, rule.getId());
    }

    @Test
    public void testName() {
        NotificationRule rule = new NotificationRule();
        rule.setName("Test Name");
        Assert.assertEquals("Test Name", rule.getName());
    }

    @Test
    public void testEnabled() {
        NotificationRule rule = new NotificationRule();
        rule.setEnabled(true);
        Assert.assertTrue(rule.isEnabled());
    }

    @Test
    public void testScope() {
        NotificationRule rule = new NotificationRule();
        rule.setScope(NotificationScope.PORTFOLIO);
        Assert.assertEquals(NotificationScope.PORTFOLIO, rule.getScope());
    }

    @Test
    public void testNotificationLevel() {
        NotificationRule rule = new NotificationRule();
        rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        Assert.assertEquals(NotificationLevel.INFORMATIONAL, rule.getNotificationLevel());
    }

    @Test
    public void testProjects() {
        List<Project> projects = new ArrayList<>();
        Project project = new Project();
        projects.add(project);
        NotificationRule rule = new NotificationRule();
        rule.setProjects(projects);
        Assert.assertEquals(1, rule.getProjects().size());
        Assert.assertEquals(project, rule.getProjects().get(0));
    }

    @Test
    public void testMessage() {
        NotificationRule rule = new NotificationRule();
        rule.setMessage("Test Message");
        Assert.assertEquals("Test Message", rule.getMessage());
    }

    @Test
    public void testNotifyOn() {
        Set<NotificationGroup> groups = new HashSet<>();
        groups.add(NotificationGroup.NEW_VULNERABLE_DEPENDENCY);
        groups.add(NotificationGroup.NEW_VULNERABILITY);
        NotificationRule rule = new NotificationRule();
        rule.setNotifyOn(groups);
        Assert.assertEquals(2, rule.getNotifyOn().size());
    }

    @Test
    public void testPublisher() {
        NotificationPublisher publisher = new NotificationPublisher();
        NotificationRule rule = new NotificationRule();
        rule.setPublisher(publisher);
        Assert.assertEquals(publisher, rule.getPublisher());
    }

    @Test
    public void testPublisherConfig() {
        NotificationRule rule = new NotificationRule();
        rule.setPublisherConfig("{ \"config\": \"configured\" }");
        Assert.assertEquals("{ \"config\": \"configured\" }", rule.getPublisherConfig());
    }

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        NotificationRule rule = new NotificationRule();
        rule.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), rule.getUuid().toString());
    }

    @Test
    public void testTeams() {
        Set<Team> teams = new HashSet<>();
        Team team = new Team();
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        var ruleTeam = rule.getTeams().stream().findFirst().orElse(null);
        Assert.assertNotNull(ruleTeam);
        Assert.assertEquals(team, ruleTeam);
    }

    @Test
    public void testManagedUsers() {
        Set<Team> teams = new HashSet<>();
        Team team = new Team();
        List<ManagedUser> managedUsers = new ArrayList<>();
        ManagedUser managedUser = new ManagedUser();
        managedUsers.add(managedUser);
        team.setManagedUsers(managedUsers);
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        var ruleTeam = rule.getTeams().stream().findFirst().orElse(null);
        Assert.assertNotNull(ruleTeam);
        Assert.assertEquals(team, ruleTeam);
        Assert.assertEquals(managedUser, ruleTeam.getManagedUsers().get(0));
    }

    @Test
    public void testLdapUsers() {
        Set<Team> teams = new HashSet<>();
        Team team = new Team();
        List<LdapUser> ldapUsers = new ArrayList<>();
        LdapUser ldapUser = new LdapUser();
        ldapUsers.add(ldapUser);
        team.setLdapUsers(ldapUsers);
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        var ruleTeam = rule.getTeams().stream().findFirst().orElse(null);
        Assert.assertNotNull(ruleTeam);
        Assert.assertEquals(team, ruleTeam);
        Assert.assertEquals(ldapUser, ruleTeam.getLdapUsers().get(0));
    }

    @Test
    public void testOidcUsers() {
        Set<Team> teams = new HashSet<>();
        Team team = new Team();
        List<OidcUser> oidcUsers = new ArrayList<>();
        OidcUser oidcUser = new OidcUser();
        oidcUsers.add(oidcUser);
        team.setOidcUsers(oidcUsers);
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        var ruleTeam = rule.getTeams().stream().findFirst().orElse(null);
        Assert.assertNotNull(ruleTeam);
        Assert.assertEquals(team, ruleTeam);
        Assert.assertEquals(oidcUser, ruleTeam.getOidcUsers().get(0));
    }

    @Test
    public void testLogSuccessfulPublish() {
        NotificationRule rule = new NotificationRule();
        rule.setLogSuccessfulPublish(true);
        Assert.assertTrue(rule.isLogSuccessfulPublish());
    }
}
