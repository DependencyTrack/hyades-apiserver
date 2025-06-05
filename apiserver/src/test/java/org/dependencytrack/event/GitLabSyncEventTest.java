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

package org.dependencytrack.event;

import alpine.model.OidcUser;
import org.junit.Assert;
import org.junit.Test;

public class GitLabSyncEventTest {

    @Test
    public void testDefaultConstructor() {
        // Arrange and Act
        GitLabSyncEvent event = new GitLabSyncEvent();

        // Assert
        Assert.assertNull(event.getAccessToken());
        Assert.assertNull(event.getUser());
    }

    @Test
    public void testParameterizedConstructor() {
        // Arrange
        String accessToken = "test-access-token";
        OidcUser user = new OidcUser();

        // Act
        GitLabSyncEvent event = new GitLabSyncEvent(accessToken, user);

        // Assert
        Assert.assertEquals(accessToken, event.getAccessToken());
        Assert.assertEquals(user, event.getUser());
    }

    @Test
    public void testSettersAndGetters() {
        // Arrange
        GitLabSyncEvent event = new GitLabSyncEvent();
        String accessToken = "test-access-token";
        OidcUser user = new OidcUser();

        // Act
        event.setAccessToken(accessToken);
        event.setUser(user);

        // Assert
        Assert.assertEquals(accessToken, event.getAccessToken());
        Assert.assertEquals(user, event.getUser());
    }

    @Test
    public void testToString() {
        // Arrange
        String accessToken = "test-access-token";
        OidcUser user = new OidcUser();
        GitLabSyncEvent event = new GitLabSyncEvent(accessToken, user);

        // Act
        String toString = event.toString();

        // Assert
        Assert.assertNotNull(toString);
        Assert.assertTrue(toString.contains("GitLabSyncEvent"));
        Assert.assertTrue(toString.contains(accessToken));
        Assert.assertTrue(toString.contains(user.toString()));
    }

    @Test
    public void testToStringWithNullValues() {
        // Arrange
        GitLabSyncEvent event = new GitLabSyncEvent();

        // Act
        String toString = event.toString();

        // Assert
        Assert.assertNotNull(toString);
        Assert.assertTrue(toString.contains("GitLabSyncEvent"));
        Assert.assertTrue(toString.contains("null"));
    }
}
