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
package org.dependencytrack.integrations.gitlab;

import org.junit.Assert;
import alpine.model.IConfigProperty;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.Team;
import java.net.URISyntaxException;
import java.io.IOException;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;


/**
 * This test suite validates the integration with the GitLab API.
 */
@RunWith(MockitoJUnitRunner.class)
public class GitLabSyncerTest extends PersistenceCapableTest {

    @Mock
    private OidcUser user;

    @Mock
    private GitLabClient gitLabClient;

    @InjectMocks
    private GitLabSyncer gitLabSyncer;

    /**
     * Validates that the integration metadata is correctly defined.
     */
    @Test
    public void testIntegrationMetadata() {
        GitLabSyncer extension = new GitLabSyncer("test_token", user, gitLabClient);
        Assert.assertEquals("GitLab", extension.name());
        Assert.assertEquals("Synchronizes user permissions from connected GitLab instance", extension.description());
    }

    /**
     * Validates that the integration is enabled when the GITLAB_ENABLED property is
     * set to true.
     */
    @Test
    public void testIsEnabled() {
        qm.createConfigProperty(
                GITLAB_ENABLED.getGroupName(),
                GITLAB_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        GitLabSyncer extension = new GitLabSyncer("test_token", user, gitLabClient);
        extension.setQueryManager(qm);
        Assert.assertTrue(extension.isEnabled());
    }

    /**
     * Validates that the integration is disabled when the GITLAB_ENABLED property
     * is set to false.
     */
    @Test
    public void testIsDisabled() {
        qm.createConfigProperty(
                GITLAB_ENABLED.getGroupName(),
                GITLAB_ENABLED.getPropertyName(),
                "false",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        GitLabSyncer extension = new GitLabSyncer("test_token", user, gitLabClient);
        extension.setQueryManager(qm);
        Assert.assertFalse(extension.isEnabled());
    }

    /**
     * Validates that the synchronize method is correctly executed when the
     * integration is enabled.
     */
    @Test
    public void testSynchronizeSuccess() {
        qm.createConfigProperty(
                GITLAB_ENABLED.getGroupName(),
                GITLAB_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        qm.createOidcUser(
                "test_user"
        );
        OidcUser testUser = new OidcUser();
        testUser.setUsername("test_user");
        GitLabClient mockClient = mock(GitLabClient.class);
        GitLabSyncer extension = new GitLabSyncer("test_token", testUser, mockClient);
        extension.setQueryManager(qm);
        try{
            when(mockClient.getGitLabProjects()).thenReturn(Arrays.asList(new GitLabProject("project1", "this/test/project1", GitLabRole.MAINTAINER),
                    new GitLabProject("project2", "that/test/project2", GitLabRole.REPORTER)));
                    extension.synchronize();
        }catch (IOException | URISyntaxException ex) {
            Assert.fail("Exception " + ex);
        }
        Project testProject1 = qm.getProject("this/test/project1", null);
        Assert.assertFalse(testProject1.isActive());

        Project testProject2 = qm.getProject("that/test/project2", null);
        Assert.assertFalse(testProject2.isActive());

        List<Team> testTeams = new ArrayList<Team>();
        Team team1 = qm.getTeam("this/test/project1_MAINTAINER");
        testTeams.add(team1);
        List<Permission> t1perm = team1.getPermissions();
        Assert.assertEquals(t1perm.size(), mockClient.getRolePermissions(GitLabRole.MAINTAINER).size());

        Team team2 = qm.getTeam("that/test/project2_REPORTER");
        testTeams.add(team2);
        List<Permission> t2perm = team2.getPermissions();
        Assert.assertEquals(t2perm.size(), mockClient.getRolePermissions(GitLabRole.REPORTER).size());
        
        for (Team team : testTeams) {
            List<OidcUser> testTeamUsers = team.getOidcUsers();
            Assert.assertEquals(testTeamUsers.size(), 1);
            Assert.assertEquals(testTeamUsers.get(0).getUsername(), "test_user");
        }
    }
}