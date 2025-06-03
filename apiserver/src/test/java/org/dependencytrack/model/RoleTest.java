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

import alpine.model.Permission;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;

public class RoleTest {

    @Test
    public void testGetAndSetId() {
        Role role = new Role();
        role.setId(123L);
        Assert.assertEquals(123L, role.getId());
    }

    @Test
    public void testGetAndSetName() {
        Role role = new Role();
        role.setName("Test Role");
        Assert.assertEquals("Test Role", role.getName());
    }

    @Test
    public void testGetAndSetPermissions() {
        Role role = new Role();
        Permission permission1 = new Permission();
        permission1.setName("Permission1");

        Permission permission2 = new Permission();
        permission2.setName("Permission2");

        Set<Permission> permissions = new LinkedHashSet<>();
        permissions.add(permission1);
        permissions.add(permission2);

        role.setPermissions(permissions);
        Assert.assertEquals(2, role.getPermissions().size());
        Assert.assertTrue(role.getPermissions().contains(permission1));
        Assert.assertTrue(role.getPermissions().contains(permission2));
    }

    @Test
    public void testAddPermissions() {
        Role role = new Role();
        Permission permission1 = new Permission();
        permission1.setName("Permission1");

        Permission permission2 = new Permission();
        permission2.setName("Permission2");

        boolean added = role.addPermissions(permission1, permission2);
        Assert.assertTrue(added);
        Assert.assertEquals(2, role.getPermissions().size());
        Assert.assertTrue(role.getPermissions().contains(permission1));
        Assert.assertTrue(role.getPermissions().contains(permission2));
    }

    @Test
    public void testAddPermissionsWithExistingPermissions() {
        Role role = new Role();
        Permission permission1 = new Permission();
        permission1.setName("Permission1");

        role.addPermissions(permission1);

        Permission permission2 = new Permission();
        permission2.setName("Permission2");

        boolean added = role.addPermissions(permission2);
        Assert.assertTrue(added);
        Assert.assertEquals(2, role.getPermissions().size());
        Assert.assertTrue(role.getPermissions().contains(permission1));
        Assert.assertTrue(role.getPermissions().contains(permission2));
    }

    @Test
    public void testGetAndSetUuid() {
        Role role = new Role();
        UUID uuid = UUID.randomUUID();
        role.setUuid(uuid);
        Assert.assertEquals(uuid, role.getUuid());
    }

    @Test
    public void testToString() {
        Role role = new Role();
        role.setName("Test Role");
        role.setUuid(UUID.fromString("123e4567-e89b-12d3-a456-426614174000"));

        Permission permission1 = new Permission();
        permission1.setName("Permission1");

        Permission permission2 = new Permission();
        permission2.setName("Permission2");

        role.addPermissions(permission1, permission2);

        String expected = "Role{uuid='123e4567-e89b-12d3-a456-426614174000', name='Test Role', permissions=[Permission1, Permission2]}";
        Assert.assertEquals(expected, role.toString());
    }
}
