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

import alpine.model.ManagedUser;
import alpine.model.Permission;
import org.dependencytrack.PersistenceCapableTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

public class UserProjectRoleTest extends PersistenceCapableTest {

    @Test
    public void testDefaultConstructor() {
        UserProjectRole userProjectRole = new UserProjectRole();
        Assertions.assertNull(userProjectRole.getUser());
        Assertions.assertNull(userProjectRole.getProject());
        Assertions.assertNull(userProjectRole.getRole());
        Assertions.assertEquals(0, userProjectRole.getId());
    }

    @Test
    public void testParameterizedConstructor() {
        final ManagedUser user = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);
        final Role role = qm.createRole("maintainer", new ArrayList<Permission>());

        final Project project = qm.createProject("test-project-1", "Test Description 1", "1.0.0", null, null,
                null,
                null, false, false);

        UserProjectRole userProjectRole = new UserProjectRole(user, project, role);

        Assertions.assertEquals(user, userProjectRole.getUser());
        Assertions.assertEquals(project, userProjectRole.getProject());
        Assertions.assertEquals(role, userProjectRole.getRole());
    }

    @Test
    public void testGetAndSetId() {
        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setId(123L);
        Assertions.assertEquals(123L, userProjectRole.getId());
    }

    @Test
    public void testGetAndSetUser() {
        final ManagedUser user = qm.createManagedUser("test-user", TEST_PASSWORD_HASH);

        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setUser(user);

        Assertions.assertEquals(user, userProjectRole.getUser());
    }

    @Test
    public void testGetAndSetProject() {
        Project project = new Project();
        project.setName("test-project");

        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setProject(project);

        Assertions.assertEquals(project, userProjectRole.getProject());
    }

    @Test
    public void testGetAndSetRole() {
        Role role = new Role();
        role.setName("test-role");

        UserProjectRole userProjectRole = new UserProjectRole();
        userProjectRole.setRole(role);

        Assertions.assertEquals(role, userProjectRole.getRole());
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
        Assertions.assertEquals(expected, userProjectRole.toString());
    }
}
