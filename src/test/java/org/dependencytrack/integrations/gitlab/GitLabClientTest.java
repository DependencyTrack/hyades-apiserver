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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import org.dependencytrack.auth.Permissions;
import org.json.JSONArray;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

public class GitLabClientTest {

    @SuppressWarnings("deprecation")
    @Test
    public void testJsonToList() {
        GitLabClient client = null;
        try {
            client = new GitLabClient(new GitLabSyncer(null, null), new URL("https://gitlab.com"));
        } catch (MalformedURLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        JSONArray jsonArray = new JSONArray();
        jsonArray.put("value1");
        jsonArray.put("value2");
        jsonArray.put("value3");
        List<String> list = client.jsonToList(jsonArray);
        assertEquals(3, list.size());
        assertEquals("value1", list.get(0));
        assertEquals("value2", list.get(1));
        assertEquals("value3", list.get(2));
    }

    @Test
    public void testJsonToListNull() throws Exception {
        @SuppressWarnings("deprecation")
        GitLabClient client = new GitLabClient(new GitLabSyncer(null, null), new URL("https://gitlab.com"));
        List<String> list = client.jsonToList(null);
        assertEquals(0, list.size());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testJsonToListEmpty() throws MalformedURLException {
        GitLabClient client = new GitLabClient(new GitLabSyncer(null, null), new URL("https://gitlab.com"));
        JSONArray jsonArray = new JSONArray();
        List<String> list = client.jsonToList(jsonArray);
        assertEquals(0, list.size());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testMapPermissionsToRoles() throws MalformedURLException {
        GitLabClient client = new GitLabClient(new GitLabSyncer(null, null), new URL("https://gitlab.com"));
        @SuppressWarnings("unchecked")
        Map<String, List<Permissions>> permissionMap = client.mapPermissionsToRoles();
        assertEquals(5, permissionMap.size());
        assertNotNull(permissionMap.get("GUEST"));
        assertNotNull(permissionMap.get("REPORTER"));
        assertNotNull(permissionMap.get("DEVELOPER"));
        assertNotNull(permissionMap.get("MAINTAINER"));
        assertNotNull(permissionMap.get("OWNER"));
    }
}