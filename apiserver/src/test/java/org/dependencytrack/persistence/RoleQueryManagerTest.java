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
import org.dependencytrack.model.ProjectRole;
import org.dependencytrack.model.Role;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.RoleDao;
import org.jdbi.v3.core.Jdbi;

import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.server.auth.PasswordService;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;

public class RoleQueryManagerTest extends PersistenceCapableTest {

    private PostgreSQLContainer<?> postgresContainer;
    private static final String TEST_ROLE_PASSWORD_HASH = new String(PasswordService.createHash("testuser".toCharArray()));

    @Before
    public void setUp() {
        System.setProperty("javax.jdo.PersistenceManagerFactoryClass",
                "org.datanucleus.api.jdo.JDOPersistenceManagerFactory");

        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"));
        postgresContainer.start();

        Jdbi.create(
                postgresContainer.getJdbcUrl(),
                postgresContainer.getUsername(),
                postgresContainer.getPassword());
    }

    @After
    public void tearDown() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void testCreateRole() {
        final var readPermission = new Permission();
        readPermission.setId(1);
        readPermission.setName("read");
        readPermission.setDescription("permission to read");
        qm.persist(readPermission);

        final var writePermission = new Permission();
        writePermission.setId(2);
        writePermission.setName("write");
        writePermission.setDescription("permission to write");
        qm.persist(writePermission);

        List<Permission> expectedPermissionsList = Arrays.asList(
                readPermission,
                writePermission);

        assertThat(qm.createRole("maintainer", expectedPermissionsList)).satisfies(
                roleCreated -> assertThat(roleCreated.getName()).isEqualTo("maintainer"));
    }

    @Test
    public void testGetRoles() {
        final var maintainerRole = new Role();
        maintainerRole.setId(1);
        maintainerRole.setName("maintainer");
        qm.persist(maintainerRole);

        final var ownerRole = new Role();
        ownerRole.setId(2);
        ownerRole.setName("owner");
        qm.persist(ownerRole);

        List<Role> expectedRoles = Arrays.asList(
                maintainerRole,
                ownerRole);

        List<Role> actualRoles = qm.getRoles();
        List<Role> actualRolesMutable = new ArrayList<Role>();
        for (Role r : actualRoles) {
            actualRolesMutable.add(r);
        }

        Assert.assertEquals(expectedRoles, actualRolesMutable);
    }

    @Test
    public void testGetRole() {
        final var wrongRole = new Role();
        wrongRole.setId(1);
        wrongRole.setName("maintainer");
        qm.persist(wrongRole);

        final var expectedRole = new Role();
        expectedRole.setId(2);
        expectedRole.setName("owner");
        qm.persist(expectedRole);

        String expectedRoleUuid = expectedRole.getUuid().toString();

        Role actualRole = qm.getRole(expectedRoleUuid);

        Assert.assertEquals(expectedRole, actualRole);
    }

    @Test
    public void testGetUserRoles() throws ParseException {
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
        testUser.setPassword(TEST_ROLE_PASSWORD_HASH);
        qm.persist(testUser);

        final var expectedRole = new Role();
        expectedRole.setId(1);
        expectedRole.setName("maintainer");
        qm.persist(expectedRole);

        JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(
                        testUser.getId(),
                        testProject.getId(),
                        expectedRole.getId()));

        List<ProjectRole> actualRoles = qm.getUserRoles(testUser);

        Assert.assertEquals(actualRoles.size(), 1);
        Assert.assertEquals(expectedRole.toString(), actualRoles.get(0).getRole().toString());
    }

    @Test
    public void testGetUnassignedProjects() throws ParseException {
        String testUserName = "test-user";

        final var testUser = new ManagedUser();
        testUser.setFullname("test user created for testing");
        testUser.setId(1);
        testUser.setUsername(testUserName);
        DateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
        testUser.setLastPasswordChange(dateFormatter.parse("20250324"));
        testUser.setPassword(TEST_ROLE_PASSWORD_HASH);
        qm.persist(testUser);

        final var maintainerRole = new Role();
        maintainerRole.setId(1);
        maintainerRole.setName("maintainer");
        qm.persist(maintainerRole);

        final var unassignedProject1 = new Project();
        unassignedProject1.setId(1);
        unassignedProject1.setName("test-project-1");
        qm.persist(unassignedProject1);

        final var assignedProject = new Project();
        assignedProject.setId(2);
        assignedProject.setName("test-project-2");

        qm.persist(assignedProject);

        final var unassignedProject2 = new Project();
        unassignedProject2.setId(3);
        unassignedProject2.setName("test-project-3");
        qm.persist(unassignedProject2);

        JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(
                        testUser.getId(),
                        assignedProject.getId(),
                        maintainerRole.getId()));

        List<Project> expectedProjects = Arrays.asList(
                unassignedProject1,
                unassignedProject2);

        List<Project> actualProjects = qm.getUnassignedProjects(testUserName);

        Assert.assertEquals(expectedProjects.toString(), actualProjects.toString());
    }

    @Test
    public void testGetUnassignedRolePermissions() throws ParseException {
        final var readPermission = new Permission();
        readPermission.setId(1);
        readPermission.setName("read");
        readPermission.setDescription("permission to read");
        qm.persist(readPermission);

        final var writePermission = new Permission();
        writePermission.setId(2);
        writePermission.setName("write");
        writePermission.setDescription("permission to write");
        qm.persist(writePermission);

        final var partyPermission = new Permission();
        partyPermission.setId(3);
        partyPermission.setName("party");
        partyPermission.setDescription("permission to party");
        qm.persist(partyPermission);

        List<Permission> expectedPermissionsList = Arrays.asList(
                readPermission,
                writePermission);

        Set<Permission> allPermissions = new HashSet<>(Arrays.asList(
                writePermission,
                writePermission,
                partyPermission));

        final var assistantRegionalManagerRole = new Role();
        assistantRegionalManagerRole.setId(1);
        assistantRegionalManagerRole.setName("maintainer");
        assistantRegionalManagerRole.setPermissions(allPermissions);
        qm.persist(assistantRegionalManagerRole);

        final var testUser = new ManagedUser();
        testUser.setFullname("test user created for testing");
        testUser.setId(1);
        testUser.setUsername("test-user");
        DateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
        testUser.setLastPasswordChange(dateFormatter.parse("20250324"));
        testUser.setPassword(TEST_ROLE_PASSWORD_HASH);
        testUser.setPermissions(expectedPermissionsList);
        qm.persist(testUser);

        List<Permission> actualPermissions = qm.getUnassignedRolePermissions(assistantRegionalManagerRole);

        Assert.assertEquals(actualPermissions.size(), 1);
        Assert.assertEquals(expectedPermissionsList.get(0), actualPermissions.get(0));
    }

    @Test
    public void testUpdateRole() {

        final var maintainerRole = new Role();
        maintainerRole.setId(1);
        maintainerRole.setName("maintainer");
        qm.persist(maintainerRole);

        Role actualRole = qm.updateRole(maintainerRole);

        Assert.assertEquals(maintainerRole, actualRole);

        // TODO: Check requirements of `updateRole`.
    }

    @Test
    public void testGetUserProjectPermissions() throws ParseException {
        final var testProject = new Project();
        testProject.setId(1);
        testProject.setName("test-project");
        testProject.setVersion("1.0.0");
        qm.persist(testProject);

        final var readPermission = new Permission();
        readPermission.setId(1);
        readPermission.setName("read");
        readPermission.setDescription("permission to read");
        qm.persist(readPermission);

        final var writePermission = new Permission();
        writePermission.setId(2);
        writePermission.setName("write");
        writePermission.setDescription("permission to write");
        qm.persist(writePermission);

        List<Permission> expectedPermissionsList = Arrays.asList(
                readPermission,
                writePermission);

        Set<Permission> expectedPermissions = new HashSet<>(expectedPermissionsList);

        final var testUser = new ManagedUser();
        testUser.setFullname("test user created for testing");
        testUser.setId(1);
        testUser.setUsername("test-user");
        DateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
        testUser.setLastPasswordChange(dateFormatter.parse("20250324"));
        testUser.setPassword(TEST_ROLE_PASSWORD_HASH);
        testUser.setPermissions(expectedPermissionsList);
        qm.persist(testUser);

        final var maintainerRole = new Role();
        maintainerRole.setId(1);
        maintainerRole.setName("maintainer");
        maintainerRole.setPermissions(expectedPermissions);
        qm.persist(maintainerRole);

        JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addPermissionToRole(
                        maintainerRole.getId(),
                        readPermission.getId()));

        JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addPermissionToRole(
                        maintainerRole.getId(),
                        writePermission.getId()));

        JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(
                        testUser.getId(),
                        testProject.getId(),
                        maintainerRole.getId()));

        List<Permission> actualPermissions = qm.getUserProjectPermissions("test-user", "test-project");
        List<Permission> actualPermissionsSorted = new ArrayList<Permission>();
        for (Permission p : actualPermissions) {
            actualPermissionsSorted.add(p);
        }
        Collections.sort(actualPermissionsSorted, Comparator.comparing(Permission::getId));

        Assert.assertEquals(expectedPermissionsList, actualPermissionsSorted);
    }

    @Test
    public void testAddRoleToUser() throws ParseException {
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
        testUser.setPassword(TEST_ROLE_PASSWORD_HASH);
        qm.persist(testUser);

        final var maintainerRole = new Role();
        maintainerRole.setId(1);
        maintainerRole.setName("maintainer");
        qm.persist(maintainerRole);

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
        testUser.setPassword(TEST_ROLE_PASSWORD_HASH);
        qm.persist(testUser);

        final var maintainerRole = new Role();
        maintainerRole.setId(1);
        maintainerRole.setName("maintainer");
        qm.persist(maintainerRole);

        JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(
                        testUser.getId(),
                        testProject.getId(),
                        maintainerRole.getId()));

        Assert.assertTrue(qm.removeRoleFromUser(testUser, maintainerRole, testProject));
    }

}
