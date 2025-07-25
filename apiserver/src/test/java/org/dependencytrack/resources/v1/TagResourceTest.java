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
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationScope;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED;
import static org.hamcrest.CoreMatchers.equalTo;

public class TagResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TagResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void getTagsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        qm.bind(projectA, List.of(tagFoo, tagBar));
        qm.bind(projectB, List.of(tagFoo));
        qm.bind(projectC, List.of(tagFoo));

        projectA.addAccessTeam(team);
        projectB.addAccessTeam(team);
        // NB: Not assigning projectC

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);
        qm.bind(policy, List.of(tagBar));

        final var notificationRuleA = new NotificationRule();
        notificationRuleA.setName("rule-a");
        notificationRuleA.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleA);

        final var notificationRuleB = new NotificationRule();
        notificationRuleB.setName("rule-b");
        notificationRuleB.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleB);

        qm.bind(notificationRuleA, List.of(tagFoo));
        // NB: Not assigning notificationRuleB

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("vuln-a");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnA);
        qm.bind(vulnA, List.of(tagFoo));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "bar",
                    "projectCount": 1,
                    "policyCount": 1,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  },
                  {
                    "name": "foo",
                    "projectCount": 2,
                    "policyCount": 0,
                    "notificationRuleCount": 1,
                    "vulnerabilityCount": 1
                  }
                ]
                """);
    }

    @Test
    public void getTagsWithPaginationTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 5; i++) {
            qm.createTag("tag-" + (i + 1));
        }

        Response response = jersey.target(V1_TAG)
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "tag-1",
                    "projectCount": 0,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  },
                  {
                    "name": "tag-2",
                    "projectCount": 0,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  },
                  {
                    "name": "tag-3",
                    "projectCount": 0,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  }
                ]
                """);

        response = jersey.target(V1_TAG)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "tag-4",
                    "projectCount": 0,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  },
                  {
                    "name": "tag-5",
                    "projectCount": 0,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  }
                ]
                """);
    }

    @Test
    public void getTagsWithFilterTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createTag("foo");
        qm.createTag("bar");

        final Response response = jersey.target(V1_TAG)
                .queryParam("filter", "O") // Should be case-insensitive.
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "foo",
                    "projectCount": 0,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  }
                ]
                """);
    }

    @Test
    public void getTagsSortByProjectCountTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        qm.bind(projectA, List.of(tagFoo, tagBar));
        qm.bind(projectB, List.of(tagFoo));

        final Response response = jersey.target(V1_TAG)
                .queryParam("sortName", "projectCount")
                .queryParam("sortOrder", "desc")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "foo",
                    "projectCount": 2,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  },
                  {
                    "name": "bar",
                    "projectCount": 1,
                    "policyCount": 0,
                    "notificationRuleCount": 0,
                    "vulnerabilityCount": 0
                  }
                ]
                """);
    }

    @Test
    public void deleteTagsTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of("foo")));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
    }

    @Test
    public void deleteTagsWhenNotExistsTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of("foo")));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) foo could not be deleted",
                  "errors": {
                    "foo": "Tag does not exist"
                  }
                }
                """);
    }

    @Test
    public void deleteTagsWhenAssignedToProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT, Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        qm.bind(project, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
    }

    @Test
    public void deleteTagsWhenAssignedToProjectWithoutPortfolioManagementPermissionTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        qm.bind(project, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 project(s), but the authenticated principal is missing the PORTFOLIO_MANAGEMENT or PORTFOLIO_MANAGEMENT_UPDATE permission."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
    }

    @Test
    public void deleteTagsWhenAssignedToInaccessibleProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT, Permissions.TAG_MANAGEMENT);

        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.bind(projectA, List.of(usedTag));
        qm.bind(projectB, List.of(usedTag));

        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 project(s) that are not accessible by the authenticated principal."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
        assertThat(qm.getTagByName("bar")).isNotNull();
    }

    @Test
    public void deleteTagsWhenAssignedToPolicyTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        qm.bind(policy, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
        assertThat(qm.getTagByName("bar")).isNull();
    }

    @Test
    public void deleteTagsWhenAssignedToPolicyWithoutPolicyManagementPermissionTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        qm.bind(policy, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 policies, but the authenticated principal is missing the POLICY_MANAGEMENT or POLICY_MANAGEMENT_UPDATE permission."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
        assertThat(qm.getTagByName("bar")).isNotNull();
    }

    @Test
    public void getTaggedProjectsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        qm.bind(projectA, List.of(tagFoo, tagBar));
        qm.bind(projectB, List.of(tagFoo));
        qm.bind(projectC, List.of(tagFoo));

        projectA.addAccessTeam(team);
        projectB.addAccessTeam(team);
        // NB: Not assigning projectC

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuidA", equalTo(projectA.getUuid().toString()))
                .withMatcher("projectUuidB", equalTo(projectB.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:projectUuidA}",
                            "name": "acme-app-a"
                          },
                          {
                            "uuid": "${json-unit.matches:projectUuidB}",
                            "name": "acme-app-b"
                          }
                        ]
                        """);
    }

    @Test
    public void getTaggedProjectsWithPaginationTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Tag tag = qm.createTag("foo");

        for (int i = 0; i < 5; i++) {
            final var project = new Project();
            project.setName("acme-app-" + (i + 1));
            qm.persist(project);

            qm.bind(project, List.of(tag));
        }

        Response response = jersey.target(V1_TAG + "/foo/project")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-1"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-2"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-3"
                  }
                ]
                """);

        response = jersey.target(V1_TAG + "/foo/project")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-4"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-5"
                  }
                ]
                """);
    }

    @Test
    public void getTaggedProjectsWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createTag("foo");
        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getTaggedProjectsWithNonLowerCaseTagNameTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Response response = jersey.target(V1_TAG + "/Foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void tagProjectsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.createTag("foo");

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);

        qm.bind(projectC, List.of(qm.createTag("bar")));

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(projectA.getUuid(), projectB.getUuid(), projectC.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).satisfiesExactly(
                projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
        assertThat(projectB.getTags()).satisfiesExactly(
                projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
        assertThat(projectC.getTags()).satisfiesExactlyInAnyOrder(
                projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"),
                projectTag -> assertThat(projectTag.getName()).isEqualTo("bar"));
    }

    @Test
    public void tagProjectsWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        final var project = new Project();
        project.setName("acme-app-a");
        qm.persist(project);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(project.getUuid())));
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
    public void tagProjectsWithNoProjectUuidsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "tagProjects.projectUuids",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void tagProjectsWithAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.createTag("foo");

        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(projectA.getUuid(), projectB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
        assertThat(projectB.getTags()).isEmpty();
    }

    @Test
    public void tagProjectsWhenAlreadyTaggedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        final var project = new Project();
        project.setName("acme-app-a");
        qm.persist(project);

        final Tag tag = qm.createTag("foo");
        qm.bind(project, List.of(tag));

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
    }

    @Test
    public void untagProjectsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final Tag tag = qm.createTag("foo");
        qm.bind(projectA, List.of(tag));
        qm.bind(projectB, List.of(tag));

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(projectA.getUuid(), projectB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).isEmpty();
        assertThat(projectB.getTags()).isEmpty();
    }

    @Test
    public void untagProjectsWithAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final Tag tag = qm.createTag("foo");
        qm.bind(projectA, List.of(tag));
        qm.bind(projectB, List.of(tag));

        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(projectA.getUuid(), projectB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).isEmpty();
        assertThat(projectB.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
    }

    @Test
    public void untagProjectsWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        final var project = new Project();
        project.setName("acme-app-a");
        qm.persist(project);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(project.getUuid())));
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
    public void untagProjectsWithNoProjectUuidsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/project")
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
                    "path": "untagProjects.projectUuids",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagProjectsWithTooManyProjectUuidsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        qm.createTag("foo");

        final List<String> projectUuids = IntStream.range(0, 101)
                .mapToObj(ignored -> UUID.randomUUID())
                .map(UUID::toString)
                .toList();

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(projectUuids));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagProjects.projectUuids",
                    "invalidValue": "${json-unit.any-string}"
                  }
                ]
                """);
    }

    @Test
    public void untagProjectsWhenNotTaggedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        final var project = new Project();
        project.setName("acme-app-a");
        qm.persist(project);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).isEmpty();
    }

    @Test
    public void getTaggedPoliciesTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);
        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

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

        qm.bind(policyA, List.of(tagFoo));
        qm.bind(policyB, List.of(tagBar));

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("policyUuidA", equalTo(policyA.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:policyUuidA}",
                            "name": "policy-a"
                          }
                        ]
                        """);
    }

    @Test
    public void getTaggedPoliciesWithPaginationTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);
        final Tag tag = qm.createTag("foo");

        for (int i = 0; i < 5; i++) {
            final var policy = new Policy();
            policy.setName("policy-" + (i + 1));
            policy.setOperator(Policy.Operator.ALL);
            policy.setViolationState(Policy.ViolationState.INFO);
            qm.persist(policy);
            qm.bind(policy, List.of(tag));
        }

        Response response = jersey.target(V1_TAG + "/foo/policy")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-1"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-2"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-3"
                  }
                ]
                """);

        response = jersey.target(V1_TAG + "/foo/policy")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-4"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-5"
                  }
                ]
                """);
    }

    @Test
    public void getTaggedPoliciesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);
        qm.createTag("foo");
        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getTaggedPoliciesWithNonLowerCaseTagNameTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);
        final Response response = jersey.target(V1_TAG + "/Foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
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

        final var policyC = new Policy();
        policyC.setName("policy-c");
        policyC.setOperator(Policy.Operator.ALL);
        policyC.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyC);

        qm.bind(policyC, List.of(qm.createTag("bar")));

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(policyA.getUuid(), policyB.getUuid(), policyC.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(policyA.getTags()).satisfiesExactly(
                policyTag -> assertThat(policyTag.getName()).isEqualTo("foo"));
        assertThat(policyB.getTags()).satisfiesExactly(
                policyTag -> assertThat(policyTag.getName()).isEqualTo("foo"));
        assertThat(policyC.getTags()).satisfiesExactlyInAnyOrder(
                policyTag -> assertThat(policyTag.getName()).isEqualTo("foo"),
                policyTag -> assertThat(policyTag.getName()).isEqualTo("bar"));
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
                    "path": "tagPolicies.policyUuids",
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
                    "path": "untagPolicies.policyUuids",
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
                    "path": "untagPolicies.policyUuids",
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

    @Test
    public void getTagsForPolicyWithOrderingTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 1; i < 5; i++) {
            qm.createTag("Tag " + i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, null, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 2"), qm.getTagByName("Tag 3"), qm.getTagByName("Tag 4")), null, null, null, false);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        Response response = jersey.target(V1_TAG + "/policy/" + policy.getUuid())
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
    public void getTagsForPolicyWithPolicyProjectsFilterTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 1; i < 5; i++) {
            qm.createTag("Tag " + i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, null, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 3")), null, null, null, false);
        qm.createProject("Project C", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 4")), null, null, null, false);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy.setProjects(List.of(qm.getProject("Project A", "1"), qm.getProject("Project C", "1")));

        Response response = jersey.target(V1_TAG + "/policy/" + policy.getUuid())
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
    public void getTagWithNonUuidNameTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        // NB: This is just to ensure that requests to /api/v1/tag/<value>
        // are not matched with the deprecated "getTagsForPolicy" endpoint.
        // Once we implement an endpoint to request individual tags,
        // this test should fail and adjusted accordingly.
        qm.createTag("not-a-uuid");

        final Response response = jersey.target(V1_TAG + "/not-a-uuid")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void deleteTagsWhenAssignedToNotificationRuleTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT, Permissions.SYSTEM_CONFIGURATION);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var notificationRule = new NotificationRule();
        notificationRule.setName("rule");
        notificationRule.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRule);

        qm.bind(notificationRule, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
        assertThat(qm.getTagByName("bar")).isNull();
    }

    @Test
    public void deleteTagsWhenAssignedToNotificationRuleWithoutSystemConfigurationPermissionTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var notificationRule = new NotificationRule();
        notificationRule.setName("rule");
        notificationRule.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRule);

        qm.bind(notificationRule, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 notification rules, but the authenticated principal is missing the SYSTEM_CONFIGURATION or SYSTEM_CONFIGURATION_UPDATE permission."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
        assertThat(qm.getTagByName("bar")).isNotNull();
    }

    @Test
    public void getTaggedNotificationRulesTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        final var notificationRuleA = new NotificationRule();
        notificationRuleA.setName("rule-a");
        notificationRuleA.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleA);

        final var notificationRuleB = new NotificationRule();
        notificationRuleB.setName("rule-b");
        notificationRuleB.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleB);

        qm.bind(notificationRuleA, List.of(tagFoo));
        qm.bind(notificationRuleB, List.of(tagBar));

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("notificationRuleUuidA", equalTo(notificationRuleA.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:notificationRuleUuidA}",
                            "name": "rule-a"
                          }
                        ]
                        """);
    }

    @Test
    public void getTaggedNotificationRulesWithPaginationTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final Tag tag = qm.createTag("foo");

        for (int i = 0; i < 5; i++) {
            final var notificationRule = new NotificationRule();
            notificationRule.setName("rule-" + (i+1));
            notificationRule.setScope(NotificationScope.PORTFOLIO);
            qm.persist(notificationRule);

            qm.bind(notificationRule, List.of(tag));
        }

        Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "rule-1"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "rule-2"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "rule-3"
                  }
                ]
                """);

        response = jersey.target(V1_TAG + "/foo/notificationRule")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "rule-4"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "rule-5"
                  }
                ]
                """);
    }

    @Test
    public void getTaggedNotificationRulesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getTaggedNotificationRulesWithNonLowerCaseTagNameTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/Foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void tagNotificationRulesTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final var notificationRuleA = new NotificationRule();
        notificationRuleA.setName("rule-a");
        notificationRuleA.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleA);

        final var notificationRuleB = new NotificationRule();
        notificationRuleB.setName("rule-b");
        notificationRuleB.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleB);

        qm.createTag("foo");

        final var notificationRuleC = new NotificationRule();
        notificationRuleC.setName("rule-c");
        notificationRuleC.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleC);

        qm.bind(notificationRuleC, List.of(qm.createTag("bar")));

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(notificationRuleA.getUuid(), notificationRuleB.getUuid(), notificationRuleC.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(notificationRuleA.getTags()).satisfiesExactly(
                ruleTag -> assertThat(ruleTag.getName()).isEqualTo("foo"));
        assertThat(notificationRuleB.getTags()).satisfiesExactly(
                ruleTag -> assertThat(ruleTag.getName()).isEqualTo("foo"));
        assertThat(notificationRuleC.getTags()).satisfiesExactlyInAnyOrder(
                ruleTag -> assertThat(ruleTag.getName()).isEqualTo("foo"),
                ruleTag -> assertThat(ruleTag.getName()).isEqualTo("bar"));
    }

    @Test
    public void tagNotificationRulesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final var notificationRule = new NotificationRule();
        notificationRule.setName("rule");
        notificationRule.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRule);

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(notificationRule.getUuid())));
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
    public void tagNotificationRulesWithNoRuleUuidsTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "tagNotificationRules.notificationRuleUuids",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagNotificationRulesTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final var notificationRuleA = new NotificationRule();
        notificationRuleA.setName("rule-a");
        notificationRuleA.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleA);

        final var notificationRuleB = new NotificationRule();
        notificationRuleB.setName("rule-b");
        notificationRuleB.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRuleB);

        final Tag tag = qm.createTag("foo");
        qm.bind(notificationRuleA, List.of(tag));
        qm.bind(notificationRuleB, List.of(tag));

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(notificationRuleA.getUuid(), notificationRuleB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(notificationRuleA.getTags()).isEmpty();
        assertThat(notificationRuleB.getTags()).isEmpty();
    }

    @Test
    public void untagNotificationRulesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final var notificationRule = new NotificationRule();
        notificationRule.setName("rule");
        notificationRule.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRule);

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(notificationRule.getUuid())));
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
    public void untagNotificationRulesWithNoProjectUuidsTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
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
                    "path": "untagNotificationRules.policyUuids",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagNotificationRulesWithTooManyRuleUuidsTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        qm.createTag("foo");

        final List<String> policyUuids = IntStream.range(0, 101)
                .mapToObj(ignored -> UUID.randomUUID())
                .map(UUID::toString)
                .toList();

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
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
                    "path": "untagNotificationRules.policyUuids",
                    "invalidValue": "${json-unit.any-string}"
                  }
                ]
                """);
    }

    @Test
    public void untagNotificationRulesWhenNotTaggedTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final var notificationRule = new NotificationRule();
        notificationRule.setName("rule");
        notificationRule.setScope(NotificationScope.PORTFOLIO);
        qm.persist(notificationRule);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/notificationRule")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(notificationRule.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(notificationRule.getTags()).isEmpty();
    }

    @Test
    public void getTaggedVulnerabilitiesTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("vuln-a");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("vuln-b");
        vulnB.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnB);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        qm.bind(vulnA, List.of(tagFoo));
        qm.bind(vulnB, List.of(tagFoo, tagBar));

        final Response response = jersey.target(V1_TAG + "/foo/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("vulnUuidA", equalTo(vulnA.getUuid().toString()))
                .withMatcher("vulnUuidB", equalTo(vulnB.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:vulnUuidA}",
                            "vulnId": "vuln-a",
                            "source": "INTERNAL"
                          },
                          {
                            "uuid": "${json-unit.matches:vulnUuidB}",
                            "vulnId": "vuln-b",
                            "source": "INTERNAL"
                          }
                        ]
                        """);
    }

    @Test
    public void getTaggedVulnerabilitiesWithPaginationTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);
        final Tag tag = qm.createTag("foo");

        for (int i = 0; i < 5; i++) {
            final var vuln = new Vulnerability();
            vuln.setVulnId("vuln-" + (i + 1));
            vuln.setSource(Vulnerability.Source.INTERNAL);
            qm.persist(vuln);
            qm.bind(vuln, List.of(tag));
        }

        Response response = jersey.target(V1_TAG + "/foo/vulnerability")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "vulnId": "vuln-1",
                    "source": "INTERNAL"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "vulnId": "vuln-2",
                    "source": "INTERNAL"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "vulnId": "vuln-3",
                    "source": "INTERNAL"
                  }
                ]
                """);

        response = jersey.target(V1_TAG + "/foo/vulnerability")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "vulnId": "vuln-4",
                    "source": "INTERNAL"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "vulnId": "vuln-5",
                    "source": "INTERNAL"
                  }
                ]
                """);
    }

    @Test
    public void getTaggedVulnerabilitiesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);
        qm.createTag("foo");
        final Response response = jersey.target(V1_TAG + "/foo/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getTaggedVulnerabilitiesWithNonLowerCaseTagNameTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);
        final Response response = jersey.target(V1_TAG + "/Foo/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void untagVulnerabilitiesTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("vuln-a");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("vuln-b");
        vulnB.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnB);

        final Tag tagFoo = qm.createTag("foo");

        qm.bind(vulnA, List.of(tagFoo));
        qm.bind(vulnB, List.of(tagFoo));

        final Response response = jersey.target(V1_TAG + "/foo/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(vulnA.getUuid(), vulnB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(vulnA.getTags()).isEmpty();
        assertThat(vulnB.getTags().isEmpty());
    }

    @Test
    public void untagVulnerabilitiesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("vuln-a");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnA);

        final Response response = jersey.target(V1_TAG + "/foo/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(vulnA.getUuid())));

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
    public void untagVulnerabilitiesWithNoVulnerabilityUuidsTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/vulnerability")
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
                    "path": "untagVulnerabilities.vulnerabilityUuids",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagVulnerabilitiesWithTooManyVulnerabilityUuidsTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);

        qm.createTag("foo");

        final List<String> vulnUuids = IntStream.range(0, 101)
                .mapToObj(ignored -> UUID.randomUUID())
                .map(UUID::toString)
                .toList();

        final Response response = jersey.target(V1_TAG + "/foo/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(vulnUuids));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagVulnerabilities.vulnerabilityUuids",
                    "invalidValue": "${json-unit.any-string}"
                  }
                ]
                """);
    }

    @Test
    public void untagVulnerabilitiesWhenNotTaggedTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("vuln-a");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnA);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(vulnA.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(vulnA.getTags()).isEmpty();
    }

    @Test
    public void deleteTagsWhenAssignedToVulnerabilityTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT, Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("vuln-a");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnA);

        qm.bind(vulnA, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
        assertThat(qm.getTagByName("bar")).isNull();
    }

    @Test
    public void deleteTagsWhenAssignedToVulnerabilityWithoutVulnerabilityManagementPermissionTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("vuln-a");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnA);

        qm.bind(vulnA, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 vulnerabilities, but the authenticated principal is missing the VULNERABILITY_MANAGEMENT or VULNERABILITY_MANAGEMENT_UPDATE permission."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
        assertThat(qm.getTagByName("bar")).isNotNull();
    }
}
