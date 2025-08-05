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

import alpine.event.framework.Event;
import alpine.model.OidcUser;
import alpine.server.auth.OidcProfile;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GitLabAuthenticationCustomizerTest {

    @Test
    public void testIsProfileComplete() {
        GitLabAuthenticationCustomizer customizer = new GitLabAuthenticationCustomizer();
        OidcProfile profile = mock(OidcProfile.class);
        boolean teamSyncEnabled = true;

        boolean result = customizer.isProfileComplete(profile, teamSyncEnabled);

        Assert.assertTrue(result);
    }

    @Test
    public void testOnAuthenticationSuccess() {
        GitLabAuthenticationCustomizer customizer = new GitLabAuthenticationCustomizer();
        OidcUser user = mock(OidcUser.class);
        OidcProfile profile = mock(OidcProfile.class);
        String idToken = "idToken";
        String accessToken = "accessToken";

        when(profile.getGroups()).thenReturn(new ArrayList<>());

        OidcUser result = customizer.onAuthenticationSuccess(user, profile, idToken, accessToken);

        Assert.assertEquals(user, result);

        // Verify that the GitLabSyncEvent was dispatched
        verify(Event.class, Mockito.times(1));
    }

    @Test
    public void testOnAuthenticationSuccess_Groups() {
        GitLabAuthenticationCustomizer customizer = new GitLabAuthenticationCustomizer();
        OidcUser user = mock(OidcUser.class);
        OidcProfile profile = mock(OidcProfile.class);
        String idToken = "idToken";
        String accessToken = "accessToken";
        List<String> groups = new ArrayList<>();
        groups.add("group1");
        groups.add("group2");

        when(profile.getGroups()).thenReturn(groups);

        OidcUser result = customizer.onAuthenticationSuccess(user, profile, idToken, accessToken);

        Assert.assertEquals(user, result);

        // Verify that the GitLabSyncEvent was dispatched
        verify(Event.class, Mockito.times(1));
    }

    @Test
    public void testOnAuthenticationSuccess_NullGroups() {
        GitLabAuthenticationCustomizer customizer = new GitLabAuthenticationCustomizer();
        OidcUser user = mock(OidcUser.class);
        OidcProfile profile = mock(OidcProfile.class);
        String idToken = "idToken";
        String accessToken = "accessToken";

        when(profile.getGroups()).thenReturn(null);

        OidcUser result = customizer.onAuthenticationSuccess(user, profile, idToken, accessToken);

        Assert.assertEquals(user, result);

        // Verify that the GitLabSyncEvent was dispatched
        verify(Event.class, Mockito.times(1));
    }
}
