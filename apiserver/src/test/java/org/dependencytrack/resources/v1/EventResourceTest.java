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
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.model.WorkflowState;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStatus.FAILED;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class EventResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(EventResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    }));

    @Test
    public void isTokenBeingProcessedTrueTest() {
        final UUID uuid = UUID.randomUUID();
        final WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(COMPLETED);
        workflowState1.setToken(uuid);
        workflowState1.setUpdatedAt(new Date());
        var workflowState1Persisted = qm.persist(workflowState1);
        final WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(workflowState1Persisted);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(PENDING);
        workflowState2.setToken(uuid);
        workflowState2.setUpdatedAt(new Date());
        qm.persist(workflowState2);

        final Response response = jersey.target(V1_EVENT + "/token/" + uuid).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        final String jsonResponse = getPlainTextBody(response);
        assertThatJson(jsonResponse).isEqualTo("""
                        {
                            "processing": true
                        }
                        """);
    }

    @Test
    public void isTokenBeingProcessedFalseTest() {
        final UUID uuid = UUID.randomUUID();
        final WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(COMPLETED);
        workflowState1.setToken(uuid);
        workflowState1.setUpdatedAt(new Date());
        var workflowState1Persisted = qm.persist(workflowState1);
        final WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(workflowState1Persisted);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(FAILED);
        workflowState2.setToken(uuid);
        workflowState2.setUpdatedAt(new Date());
        qm.persist(workflowState2);

        final Response response = jersey.target(V1_EVENT + "/token/" + uuid).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        final String jsonResponse = getPlainTextBody(response);
        assertThatJson(jsonResponse).isEqualTo("""
                {
                    "processing": false
                }
                """);
    }

    @Test
    public void isTokenBeingProcessedNotExistsTest() {
        final Response response = jersey.target(V1_EVENT + "/token/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        final String jsonResponse = getPlainTextBody(response);
        assertThatJson(jsonResponse).isEqualTo("""
                        {
                            "processing": false
                        }
                        """);
    }

    @Test
    public void isTokenBeingProcessedShouldReturnTrueWhenWorkflowRunExistsAndHasNonTerminalStatus() {
        final var runMetadata = new WorkflowRunMetadata(
                UUID.fromString("97282c4b-70fc-4169-be01-35e7bbe4c9e8"),
                "dummy",
                1,
                WorkflowRunStatus.CREATED,
                null,
                0,
                null,
                null,
                null,
                Instant.ofEpochMilli(666666),
                null,
                null,
                null);

        doReturn(runMetadata).when(DEX_ENGINE_MOCK).getRunMetadata(
                eq(UUID.fromString("97282c4b-70fc-4169-be01-35e7bbe4c9e8")));

        final Response response = jersey.target(V1_EVENT + "/token/97282c4b-70fc-4169-be01-35e7bbe4c9e8").request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "processing": true
                }
                """);
    }

    @Test
    public void isTokenBeingProcessedShouldReturnFalseWhenWorkflowRunExistsAndHasTerminalStatus() {
        final var runMetadata = new WorkflowRunMetadata(
                UUID.fromString("97282c4b-70fc-4169-be01-35e7bbe4c9e8"),
                "dummy",
                1,
                WorkflowRunStatus.COMPLETED,
                null,
                0,
                null,
                null,
                null,
                Instant.ofEpochMilli(666666),
                Instant.ofEpochMilli(888888),
                Instant.ofEpochMilli(777777),
                Instant.ofEpochMilli(888888));

        doReturn(runMetadata).when(DEX_ENGINE_MOCK).getRunMetadata(
                eq(UUID.fromString("97282c4b-70fc-4169-be01-35e7bbe4c9e8")));

        final Response response = jersey.target(V1_EVENT + "/token/97282c4b-70fc-4169-be01-35e7bbe4c9e8").request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "processing": false
                }
                """);
    }

}
