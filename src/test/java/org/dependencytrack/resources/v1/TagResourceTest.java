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
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Policy;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.ws.rs.core.Response;
import java.util.List;

public class TagResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TagResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    public void getAllTagsWithOrderingTest() {
        for (int i=1; i<5; i++) {
            qm.createTag("Tag "+i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, true, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 2"), qm.getTagByName("Tag 3"), qm.getTagByName("Tag 4")), null, null, true, false);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        Response response = jersey.target(V1_TAG + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Assert.assertEquals(200, response.getStatus());
        Assert.assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(4, json.size());
        Assert.assertEquals("tag 2", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getTagsWithPolicyProjectsFilterTest() {
        for (int i=1; i<5; i++) {
            qm.createTag("Tag "+i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, true, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 3")), null, null, true, false);
        qm.createProject("Project C", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 4")), null, null, true, false);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy.setProjects(List.of(qm.getProject("Project A", "1"), qm.getProject("Project C", "1")));

        Response response = jersey.target(V1_TAG + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Assert.assertEquals(200, response.getStatus());
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("tag 1", json.getJsonObject(0).getString("name"));
    }
}
