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

import alpine.model.IConfigProperty;
import alpine.model.Permission;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Role;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class GitLabIntegrationStateChangerTest extends PersistenceCapableTest {

    private GitLabIntegrationStateChanger stateChanger;
    private List<Role> roles;

    @Before
    public void setUp() {
        stateChanger = new GitLabIntegrationStateChanger();
    }

    /**
     * Validates that the metadata is correctly defined.
     */
    @Test
    public void testIntegrationStateChangerMetadata() {
        Assert.assertEquals("GitLab Integration State Changer", stateChanger.name());
        Assert.assertEquals("Executes GitLab integration enable and disable tasks", stateChanger.description());
    }

    /**
     * Validates that the when integration is enabled the roles are created.
     */
    @Test
    public void testEnable() {
        stateChanger.setQueryManager(qm);
        qm.createConfigProperty(
                GITLAB_ENABLED.getGroupName(),
                GITLAB_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null);
        stateChanger.setState(true);
        roles = qm.getRoles();
        Assert.assertEquals(roles.size(), GitLabRole.values().length);
        for (GitLabRole role : GitLabRole.values()) {
            Assert.assertNotNull(qm.getRoleByName(role.getDescription()));
        }
    }

    /**
     * Validates that the when integration is disabled the roles are removed.
     */
    @Test
    public void testDisable() {
        stateChanger.setQueryManager(qm);
        qm.createConfigProperty(
                GITLAB_ENABLED.getGroupName(),
                GITLAB_ENABLED.getPropertyName(),
                "false",
                IConfigProperty.PropertyType.BOOLEAN,
                null);

        // Create roles to be removed
        stateChanger.setState(true);
        roles = qm.getRoles();
        Assert.assertEquals(roles.size(), GitLabRole.values().length);
        for (GitLabRole role : GitLabRole.values()) {
            Assert.assertNotNull(qm.getRoleByName(role.getDescription()));
        }

        // Disable the integration
        // and verify that the roles are removed
        stateChanger.setState(false);
        roles = qm.getRoles();
        Assert.assertEquals(roles.size(), 0);
    }

    @Test
    public void testPopulatePermissionsMap() {
        final var mockStateChanger = mock(GitLabIntegrationStateChanger.class);

        // Create Permission and add it to the map
        Permission permission = new Permission();
        permission.setName("VIEW_PORTFOLIO");
        Map<String, Permission> testPermissionsMap = new HashMap<String, Permission>();
        testPermissionsMap.put("VIEW_PORTFOLIO", permission);

        // Set query manager and permissions map for mockStateChanger
        mockStateChanger.setQueryManager(qm);
        when(mockStateChanger.getPermissionsMap()).thenReturn(testPermissionsMap);

        // Verify that the permission was added to the map
        Map<String, Permission> permissionsMap = mockStateChanger.getPermissionsMap();
        Assert.assertEquals(permissionsMap.size(), 1);
        Assert.assertTrue(permissionsMap.containsKey("VIEW_PORTFOLIO"));
        Assert.assertTrue(permissionsMap.containsValue(permission));
    }

}
