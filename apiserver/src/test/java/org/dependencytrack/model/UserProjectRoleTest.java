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

import java.util.ArrayList;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Assert;
import org.junit.Test;

import alpine.model.ManagedUser;
import alpine.model.Permission;

public class UserProjectRoleTest extends PersistenceCapableTest {

    @Test
    public void testDefaultConstructor() {
        UserProjectRole userProjectRole = new UserProjectRole();
        Assert.assertNull(userProjectRole.getUser());
        Assert.assertNull(userProjectRole.getProject());
        Assert.assertNull(userProjectRole.getRole());
        Assert.assertEquals(0, userProjectRole.getId());
    }

    @Test
    public void testParameterizedConstructor() {
        final ManagedUser user = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);
        final Role role = qm.createRole("maintainer", new ArrayList<Permission>());

        final Project project = qm.createProject("test-project-1", "Test Description 1", "1.0.0", null, null,
                null,
                null, false, false);

        UserProjectRole userProjectRole = new UserProjectRole(user, project, role);

        Assert.assertEquals(user, userProjectRole.getUser());
        Assert.assertEquals(project, userProjectRole.getProject());
        Assert.assertEquals(role, userProjectRole.getRole());
    }

    @Test
    public void testGetAndSetId() {
        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setId(123L);
        Assert.assertEquals(123L, userProjectRole.getId());
    }

    @Test
    public void testGetAndSetUser() {
        final ManagedUser user = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);

        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setUser(user);

        Assert.assertEquals(user, userProjectRole.getUser());
    }

    @Test
    public void testGetAndSetProject() {
        Project project = new Project();
        project.setName("test-project");

        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setProject(project);

        Assert.assertEquals(project, userProjectRole.getProject());
    }

    @Test
    public void testGetAndSetRole() {
        Role role = new Role();
        role.setName("test-role");

        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setRole(role);

        Assert.assertEquals(role, userProjectRole.getRole());
    }

    @Test
    public void testToString() {
        final ManagedUser user = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);

        Project project = new Project();
        project.setName("test-project");

        Role role = new Role();
        role.setName("test-role");

        UserProjectRole userProjectRole = new UserProjectRole(user, project, role);

        String expected = "UserProjectRole{user='test-user', project='test-project', role='test-role'}";
        Assert.assertEquals(expected, userProjectRole.toString());
    }
}
