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
import jakarta.json.JsonArray;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Tag;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

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

    @Test
    public void tagPoliciesTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policyA = new Policy();
        policyA.setName("policy-a");
        policyA.setOperator(Policy.Operator.ALL);
        policyA.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyA);

        final var policyB = new Policy();
        policyB.setName("policy-b");
        policyB.setOperator(Policy.Operator.ALL);
        policyB.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyB);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(policyA.getUuid(), policyB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(policyA.getTags()).satisfiesExactly(policyTag -> assertThat(policyTag.getName()).isEqualTo("foo"));
        assertThat(policyB.getTags()).satisfiesExactly(policyTag -> assertThat(policyTag.getName()).isEqualTo("foo"));
    }

    @Test
    public void tagPoliciesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(policy.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "A tag with name foo does not exist"
                }
                """);
    }

    @Test
    public void tagPoliciesWithNoPolicyUuidsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "tagPolicies.arg1",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagPoliciesTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policyA = new Policy();
        policyA.setName("policy-a");
        policyA.setOperator(Policy.Operator.ALL);
        policyA.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyA);

        final var policyB = new Policy();
        policyB.setName("policy-b");
        policyB.setOperator(Policy.Operator.ALL);
        policyB.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyB);

        final Tag tag = qm.createTag("foo");
        qm.bind(policyA, List.of(tag));
        qm.bind(policyB, List.of(tag));

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(policyA.getUuid(), policyB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(policyA.getTags()).isEmpty();
        assertThat(policyB.getTags()).isEmpty();
    }

    @Test
    public void untagPoliciesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(policy.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "A tag with name foo does not exist"
                }
                """);
    }

    @Test
    public void untagPoliciesWithNoProjectUuidsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagPolicies.arg1",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagPoliciesWithTooManyPolicyUuidsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        qm.createTag("foo");

        final List<String> policyUuids = IntStream.range(0, 101)
                .mapToObj(ignored -> UUID.randomUUID())
                .map(UUID::toString)
                .toList();

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(policyUuids));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagPolicies.arg1",
                    "invalidValue": "${json-unit.any-string}"
                  }
                ]
                """);
    }

    @Test
    public void untagPoliciesWhenNotTaggedTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(policy.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(policy.getTags()).isEmpty();
    }
}
