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
package org.dependencytrack.persistence;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.model.UserProjectRole;

import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.server.auth.PasswordService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Assert;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class RoleQueryManagerTest extends PersistenceCapableTest {

    private static final String TEST_ROLE_PASSWORD_HASH = new String(
            PasswordService.createHash("testuser".toCharArray()));

    @Test
    public void testCreateRole() {
        final Permission readPermission = qm.createPermission("read", "permission to read");
        final Permission writePermission = qm.createPermission("write", "permission to write");

        List<Permission> expectedPermissionsList = Arrays.asList(
                readPermission,
                writePermission);

        assertThat(qm.createRole("maintainer", expectedPermissionsList)).satisfies(
                roleCreated -> assertThat(roleCreated.getName()).isEqualTo("maintainer"));
    }

    @Test
    public void testGetRoles() {
        final Role maintainerRole = qm.createRole("maintainer", new ArrayList<Permission>());
        final Role ownerRole = qm.createRole("owner", new ArrayList<Permission>());

        List<Role> expectedRoles = Arrays.asList(
                maintainerRole,
                ownerRole);

        List<Role> actualRoles = qm.getRoles();

        Assert.assertNotNull(actualRoles);
        Assert.assertFalse(actualRoles.isEmpty());
        Assert.assertEquals(expectedRoles, actualRoles);
    }

    @Test
    public void testGetRole() {
        final Role wrongRole = qm.createRole("maintainer", new ArrayList<Permission>());
        final Role expectedRole = qm.createRole("owner", new ArrayList<Permission>());

        String expectedRoleUuid = expectedRole.getUuid().toString();

        Role actualRole = qm.getRole(expectedRoleUuid);

        Assert.assertEquals(expectedRole, actualRole);
    }

    @Test
    public void testGetUserRoles() throws ParseException {
        final Project testProject = qm.createProject("test-project", "Test Description", "1.0.0", null, null, null,
                null, false, false);
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_ROLE_PASSWORD_HASH);
        final Role expectedRole = qm.createRole("maintainer", new ArrayList<Permission>());

        qm.addRoleToUser(testUser, expectedRole, testProject);

        List<UserProjectRole> actualRoles = qm.getUserRoles(testUser);

        Assert.assertEquals(actualRoles.size(), 1);
        Assert.assertEquals(expectedRole.toString(), actualRoles.get(0).getRole().toString());
    }

    @Test
    public void testGetUnassignedProjects() throws ParseException {
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_ROLE_PASSWORD_HASH);
        final Role maintainerRole = qm.createRole("maintainer", new ArrayList<Permission>());

        final Project unassignedProject1 = qm.createProject("test-project-1", "Test Description 1", "1.0.0", null, null,
                null,
                null, false, false);

        final Project unassignedProject2 = qm.createProject("test-project-2", "Test Description 3", "1.0.0", null, null,
                null,
                null, false, false);

        final Project assignedProject = qm.createProject("test-project-3", "Test Description 2", "1.0.0", null, null,
                null,
                null, false, false);

        qm.addRoleToUser(testUser, maintainerRole, assignedProject);

        List<Project> expectedProjects = Arrays.asList(unassignedProject1, unassignedProject2);
        List<Project> actualProjects = qm.getUnassignedProjects(testUser.getUsername());

        // Sort both lists by project name before asserting equivalence
        expectedProjects.sort((p1, p2) -> p1.getName().compareTo(p2.getName()));
        actualProjects.sort((p1, p2) -> p1.getName().compareTo(p2.getName()));

        Assert.assertEquals(expectedProjects.size(), actualProjects.size());
        for (int i = 0; i < expectedProjects.size(); i++) {
            Assert.assertEquals(expectedProjects.get(i).getName(), actualProjects.get(i).getName());
        }
    }

    @Test
    public void testGetUnassignedRolePermissions() throws ParseException {
        final Permission readPermission = qm.createPermission("read", "permission to read");
        final Permission writePermission = qm.createPermission("write", "permission to write");
        final Permission partyPermission = qm.createPermission("party", "permission to party");

        List<Permission> expectedPermissionsList = Arrays.asList(
                readPermission,
                writePermission);

        Set<Permission> allPermissions = new HashSet<>(Arrays.asList(
                writePermission,
                writePermission,
                partyPermission));

        final Role assistantRegionalManagerRole = qm.createRole("maintainer", allPermissions.stream().toList());

        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_ROLE_PASSWORD_HASH);
        testUser.setPermissions(expectedPermissionsList);
        qm.persist(testUser);

        List<Permission> actualPermissions = qm.getUnassignedRolePermissions(assistantRegionalManagerRole);

        Assert.assertEquals(actualPermissions.size(), 1);
        Assert.assertEquals(expectedPermissionsList.get(0), actualPermissions.get(0));
    }

    @Test
    public void testUpdateRole() {

        final Role maintainerRole = qm.createRole("maintainer", new ArrayList<Permission>());

        Role actualRole = qm.updateRole(maintainerRole);

        Assert.assertEquals(maintainerRole, actualRole);
    }

    @Test
    public void testAddRoleToUser() throws ParseException {
        final Project testProject = qm.createProject("test-project", "Test Description", "1.0.0", null, null, null,
                null, false, false);
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_ROLE_PASSWORD_HASH);
        final Role maintainerRole = qm.createRole("maintainer", new ArrayList<Permission>());

        qm.addRoleToUser(testUser, maintainerRole, testProject);

        Assert.assertEquals(
                qm.getRoles().size(),
                1);
        Assert.assertEquals(
                qm.getRoles().get(0).getName(),
                maintainerRole.getName());
    }

    @Test
    public void testRemoveRoleFromUser() throws ParseException {
        final Project testProject = qm.createProject("test-project", "Test Description", "1.0.0", null, null, null,
                null, false, false);
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_ROLE_PASSWORD_HASH);
        final Role maintainerRole = qm.createRole("maintainer", new ArrayList<Permission>());

        qm.addRoleToUser(testUser, maintainerRole, testProject);
        Assert.assertTrue(qm.removeRoleFromUser(testUser, maintainerRole, testProject));
    }

}
