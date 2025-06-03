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

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Assert;
import org.junit.Test;

public class RoleQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testCreateRoleWithEmptyPermissions() {
        Role role = qm.createRole("empty-role", new ArrayList<>());
        Assert.assertNotNull(role);
        Assert.assertEquals("empty-role", role.getName());
        Assert.assertTrue(role.getPermissions().isEmpty());
    }

    @Test
    public void testCreateRoleWithPermissions() {
        Permission readPermission = qm.createPermission("read", "permission to read");
        Permission writePermission = qm.createPermission("write", "permission to write");

        List<Permission> permissions = Arrays.asList(readPermission, writePermission);
        Role role = qm.createRole("role-with-permissions", permissions);

        Assert.assertNotNull(role);
        Assert.assertEquals("role-with-permissions", role.getName());
        Assert.assertEquals(2, role.getPermissions().size());
        Assert.assertTrue(role.getPermissions().contains(readPermission));
        Assert.assertTrue(role.getPermissions().contains(writePermission));
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
    public void testGetRolesReturnsEmptyList() {
        List<Role> roles = qm.getRoles();
        Assert.assertNotNull(roles);
        Assert.assertTrue(roles.isEmpty());
    }

    @Test
    public void testGetRoleByUuid() {
        Role role = qm.createRole("test-role", new ArrayList<>());
        String uuid = role.getUuid().toString();

        Role fetchedRole = qm.getRole(uuid);
        Assert.assertNotNull(fetchedRole);
        Assert.assertEquals(role, fetchedRole);
    }

    @Test
    public void testGetRoleByUuidNotFound() {
        UUID nonExistentUuid = UUID.randomUUID();
        Role fetchedRole = qm.getRole(nonExistentUuid.toString());
        Assert.assertNull(fetchedRole);
    }

    @Test
    public void testAddRoleToUser() throws ParseException {
        final Project testProject = qm.createProject("test-project", "Test Description", "1.0.0", null, null, null,
                null, false, false);
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);
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
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);
        final Role maintainerRole = qm.createRole("maintainer", new ArrayList<Permission>());

        qm.addRoleToUser(testUser, maintainerRole, testProject);
        Assert.assertTrue(qm.removeRoleFromUser(testUser, maintainerRole, testProject));
    }

    @Test
    public void testGetUserRoles() throws ParseException {
        final Project testProject = qm.createProject("test-project", "Test Description", "1.0.0", null, null, null,
                null, false, false);
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);
        final Role expectedRole = qm.createRole("maintainer", new ArrayList<Permission>());

        qm.addRoleToUser(testUser, expectedRole, testProject);

        List<UserProjectRole> actualRoles = qm.getUserRoles(testUser.getUsername());

        Assert.assertEquals(actualRoles.size(), 1);
        Assert.assertEquals(expectedRole.toString(), actualRoles.get(0).getRole().toString());
    }

    @Test
    public void testGetUnassignedProjects() throws ParseException {
        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);
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
    public void testUpdateRole() {

        final Role maintainerRole = qm.createRole("maintainer", new ArrayList<Permission>());

        Role actualRole = qm.updateRole(maintainerRole);

        Assert.assertEquals(maintainerRole, actualRole);
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

        final ManagedUser testUser = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);
        testUser.setPermissions(expectedPermissionsList);
        qm.persist(testUser);

        List<Permission> actualPermissions = qm.getUnassignedRolePermissions(assistantRegionalManagerRole);

        Assert.assertEquals(actualPermissions.size(), 1);
        Assert.assertEquals(expectedPermissionsList.get(0), actualPermissions.get(0));
    }

}
