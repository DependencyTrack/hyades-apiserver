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
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class PolicyConditionResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(PolicyConditionResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    public void testCreateExpressionCondition() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        final Response response = jersey.target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "subject": "EXPRESSION",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(201);
        var response1 = getPlainTextBody(response);
        assertThatJson(response1)
                .isEqualTo("""
                        {
                        "policy":{
                        "name":"policy",
                        "operator":"ANY",
                        "violationState":"FAIL",
                        "uuid":"${json-unit.any-string}",
                        "includeChildren":false,
                        "global":true
                        },
                          "uuid": "${json-unit.any-string}",
                          "subject": "EXPRESSION",
                          "operator": "MATCHES",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """);
    }

    @Test
    public void testCreateExpressionConditionWithError() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        final Response response = jersey.target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "subject": "EXPRESSION",
                          "value": "component.doesNotExist == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "celErrors": [
                            {
                              "line": 1,
                              "column": 9,
                              "message": "undefined field 'doesNotExist'"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testUpdateExpressionCondition() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "foobar");

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("""
                        {
                          "uuid": "%s",
                          "subject": "EXPRESSION",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "OPERATIONAL"
                        }
                        """.formatted(condition.getUuid()), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "uuid": "${json-unit.any-string}",
                          "subject": "EXPRESSION",
                          "operator": "MATCHES",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "OPERATIONAL"
                        }
                        """);
    }

    @Test
    public void testUpdateExpressionConditionWithError() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "foobar");

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("""
                        {
                          "uuid": "%s",
                          "subject": "EXPRESSION",
                          "value": "component.doesNotExist == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """.formatted(condition.getUuid()), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "celErrors": [
                            {
                              "line": 1,
                              "column": 9,
                              "message": "undefined field 'doesNotExist'"
                            }
                          ]
                        }
                        """);
    }

}