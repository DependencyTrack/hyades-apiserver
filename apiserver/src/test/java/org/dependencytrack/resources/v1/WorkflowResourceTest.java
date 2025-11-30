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
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.model.WorkflowState;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.json;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

public class WorkflowResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(WorkflowResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(MultiPartFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    }));

    @After
    @Override
    public void after() {
        reset(DEX_ENGINE_MOCK);
        super.after();
    }

    @Test
    public void getWorkflowStatusOk() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(COMPLETED);
        workflowState1.setToken(uuid);
        workflowState1.setUpdatedAt(new Date());
        var workflowState1Persisted = qm.persist(workflowState1);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(workflowState1Persisted);
        workflowState2.setFailureReason(null);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(PENDING);
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState2);

        Response response = jersey.target(V1_WORKFLOW + "/token/" + uuid + "/status").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        final String jsonResponse = getPlainTextBody(response);
        assertThatJson(jsonResponse)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("token", equalTo(uuid.toString()))
                .withMatcher("step1", equalTo("BOM_CONSUMPTION"))
                .withMatcher("status1", equalTo("COMPLETED"))
                .withMatcher("step2", equalTo("BOM_PROCESSING"))
                .withMatcher("status2", equalTo("PENDING"))
                .isEqualTo(json("""
                    [{
                        "token": "${json-unit.matches:token}",
                        "step": "${json-unit.matches:step1}",
                        "status": "${json-unit.matches:status1}",
                        "updatedAt": "${json-unit.any-number}"
                    },
                    {
                        "token": "${json-unit.matches:token}",
                        "startedAt": "${json-unit.any-number}",
                        "updatedAt": "${json-unit.any-number}",
                        "step": "${json-unit.matches:step2}",
                        "status": "${json-unit.matches:status2}"
                    }]
                """));
    }

    @Test
    public void getWorkflowStatusNotFound() {
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(COMPLETED);
        workflowState1.setToken(UUID.randomUUID());
        workflowState1.setUpdatedAt(new Date());
        qm.persist(workflowState1);

        UUID randomUuid = UUID.randomUUID();
        Response response = jersey.target(V1_WORKFLOW + "/token/" + randomUuid + "/status").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(getPlainTextBody(response)).isEqualTo("Provided token " + randomUuid + " does not exist.");
    }

    @Test
    public void shouldReturnMovedPermanentlyWhenWorkflowRunWasFoundButCanNotBeConverted() {
        final WorkflowRunMetadata runMetadata = new WorkflowRunMetadata(
                UUID.fromString("f5cd00be-417d-4df5-b351-0499d498c9c1"),
                "test-workflow",
                1,
                WorkflowRunStatus.RUNNING,
                null,
                0,
                null,
                null,
                null,
                Instant.ofEpochMilli(666666),
                Instant.ofEpochMilli(777777),
                Instant.ofEpochMilli(777777),
                null);

        doReturn(runMetadata).when(DEX_ENGINE_MOCK).getRunMetadata(
                eq(UUID.fromString("f5cd00be-417d-4df5-b351-0499d498c9c1")));

        final Response response = jersey.target(V1_WORKFLOW + "/token/f5cd00be-417d-4df5-b351-0499d498c9c1/status")
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(301);
        assertThat(response.getLocation().getPath()).isEqualTo("/api/v2/workflow-runs/f5cd00be-417d-4df5-b351-0499d498c9c1");
    }

}
