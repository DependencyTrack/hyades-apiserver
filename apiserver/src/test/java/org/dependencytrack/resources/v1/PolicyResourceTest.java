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

import alpine.common.util.UuidUtil;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import static java.util.Collections.singletonList;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class PolicyResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(PolicyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    @Test
    public void getPoliciesTest() {
        for (int i = 0; i < 1000; i++) {
            qm.createPolicy("policy" + i, Policy.Operator.ANY, Policy.ViolationState.INFO);
        }

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1000");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).isNotNull();
        assertThat(json).hasSize(100);
        assertThat(json.getJsonObject(0).getString("name")).isEqualTo("policy0");
    }

    @Test
    public void getPolicyByUuidTest() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
    }

    @Test
    public void createPolicyTest() {
        final Policy policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ANY");
        assertThat(json.getString("violationState")).isEqualTo("INFO");
        assertThat(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(json.getBoolean("includeChildren")).isEqualTo(false);
    }

    @Test
    public void createPolicySpecifyOperatorAndViolationStateTest() {
        final Policy policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.FAIL);

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ALL");
        assertThat(json.getString("violationState")).isEqualTo("FAIL");
        assertThat(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(json.getBoolean("includeChildren")).isEqualTo(false);
    }

    @Test
    public void createPolicyUseDefaultValueTest() {
        final Policy policy = new Policy();
        policy.setName("policy");

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ANY");
        assertThat(json.getString("violationState")).isEqualTo("INFO");
        assertThat(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(json.getBoolean("includeChildren")).isEqualTo(false);
    }

    @Test
    public void updatePolicyTest() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        policy.setViolationState(Policy.ViolationState.FAIL);
        policy.setIncludeChildren(true);
        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ANY");
        assertThat(json.getString("violationState")).isEqualTo("FAIL");
        assertThat(json.getBoolean("includeChildren")).isEqualTo(true);
    }

    @Test
    public void deletePolicyTest() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(Policy.class, policy.getUuid())).isNull();
    }

    /**
     * This test verifies that associated conditions and violations get deleted as well when deleting a Policy.
     */
    @Test
    public void deletePolicyCascadingTest() {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "<coordinates>");

        PolicyViolation violation = new PolicyViolation();
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setType(PolicyViolation.Type.OPERATIONAL);
        violation.setTimestamp(new Date());
        qm.persist(violation);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(Policy.class, policy.getUuid())).isNull();
        assertThat(qm.getObjectByUuid(PolicyCondition.class, condition.getUuid())).isNull();
    }

    @Test
    public void addProjectToPolicyTest() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonObject json = parseJsonObject(response);
        assertThat(json.getJsonArray("projects")).hasSize(1);
        assertThat(json.getJsonArray("projects").get(0).asJsonObject().getString("uuid")).isEqualTo(project.getUuid().toString());
    }

    @Test
    public void addProjectToPolicyProjectAlreadyAddedTest() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        policy.setProjects(singletonList(project));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(304);
    }

    @Test
    public void addProjectToPolicyAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void removeProjectFromPolicyTest() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        policy.setProjects(singletonList(project));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void removeProjectFromPolicyProjectAlreadyRemovedTest() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(304);
    }

    @Test
    public void removeProjectFromPolicyAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(project));
        qm.persist(policy);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

}
