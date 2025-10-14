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
import org.junit.Test;

import java.util.Set;

public class GitLabRoleTest {

    @Test
    public void testGetAccessLevel() {
        Assert.assertEquals(10, GitLabRole.GUEST.getAccessLevel());
        Assert.assertEquals(15, GitLabRole.PLANNER.getAccessLevel());
        Assert.assertEquals(20, GitLabRole.REPORTER.getAccessLevel());
        Assert.assertEquals(30, GitLabRole.DEVELOPER.getAccessLevel());
        Assert.assertEquals(40, GitLabRole.MAINTAINER.getAccessLevel());
        Assert.assertEquals(50, GitLabRole.OWNER.getAccessLevel());
    }

    @Test
    public void testGetDescription() {
        Assert.assertEquals("GitLab Project Guest", GitLabRole.GUEST.getDescription());
        Assert.assertEquals("GitLab Project Planner", GitLabRole.PLANNER.getDescription());
        Assert.assertEquals("GitLab Project Reporter", GitLabRole.REPORTER.getDescription());
        Assert.assertEquals("GitLab Project Developer", GitLabRole.DEVELOPER.getDescription());
        Assert.assertEquals("GitLab Project Maintainer", GitLabRole.MAINTAINER.getDescription());
        Assert.assertEquals("GitLab Project Owner", GitLabRole.OWNER.getDescription());
    }

    @Test
    public void testGetPermissionsForGuest() {
        Set<String> permissions = GitLabRole.GUEST.getPermissions();
        Assert.assertEquals(2, permissions.size());
    }

    @Test
    public void testGetPermissionsForPlanner() {
        Set<String> permissions = GitLabRole.PLANNER.getPermissions();
        Assert.assertEquals(3, permissions.size());
    }

    @Test
    public void testGetPermissionsForReporter() {
        Set<String> permissions = GitLabRole.REPORTER.getPermissions();
        Assert.assertEquals(4, permissions.size());
    }

    @Test
    public void testGetPermissionsForDeveloper() {
        Set<String> permissions = GitLabRole.DEVELOPER.getPermissions();
        Assert.assertEquals(8, permissions.size());
    }

    @Test
    public void testGetPermissionsForMaintainer() {
        Set<String> permissions = GitLabRole.MAINTAINER.getPermissions();
        Assert.assertEquals(12, permissions.size());
    }

    @Test
    public void testGetPermissionsForOwner() {
        Set<String> permissions = GitLabRole.OWNER.getPermissions();
        Assert.assertEquals(13, permissions.size());
    }
}
