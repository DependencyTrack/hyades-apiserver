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
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.model.WorkflowState;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class WorkflowResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
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

    @AfterEach
    void afterEach() {
        Mockito.reset(DEX_ENGINE_MOCK);
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

        Response response = jersey
                .target(V1_WORKFLOW + "/token/" + uuid + "/status")
                .request()
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
                .isEqualTo(/* language=JSON */ """
                        [
                          {
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
                          }
                        ]
                        """);
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

    @ParameterizedTest
    @CsvSource({
            "CREATED, PENDING",
            "RUNNING, PENDING",
            "SUSPENDED, PENDING",
            "CANCELLED, CANCELLED",
            "COMPLETED, COMPLETED",
            "FAILED, FAILED",
    })
    void shouldReturnLegacyWorkflowStateForVulnAnalysisDexRun(
            WorkflowRunStatus dexStatus, String expectedLegacyStatus) {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var runMetadata = new WorkflowRunMetadata(
                UUID.fromString("a3c39f8a-0c02-4a8c-8a3a-2f77e203809c"),
                "vuln-analysis",
                1,
                null,
                "taskQueue",
                dexStatus,
                null,
                0,
                null,
                null,
                Instant.ofEpochMilli(1234567000),
                Instant.ofEpochMilli(1234567890),
                null,
                null);

        doReturn(runMetadata)
                .when(DEX_ENGINE_MOCK).getRunMetadataById(
                        eq(UUID.fromString("a3c39f8a-0c02-4a8c-8a3a-2f77e203809c")));

        final Response response = jersey
                .target(V1_WORKFLOW + "/token/a3c39f8a-0c02-4a8c-8a3a-2f77e203809c/status")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "token": "a3c39f8a-0c02-4a8c-8a3a-2f77e203809c",
                    "step": "VULN_ANALYSIS",
                    "status": "%s",
                    "updatedAt": 1234567890
                  }
                ]
                """.formatted(expectedLegacyStatus));
    }

    @Test
    void shouldReturnLegacyWorkflowStateWithNullUpdatedAtForVulnAnalysisDexRun() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var runMetadata = new WorkflowRunMetadata(
                UUID.fromString("a3c39f8a-0c02-4a8c-8a3a-2f77e203809c"),
                "vuln-analysis",
                1,
                null,
                "taskQueue",
                WorkflowRunStatus.RUNNING,
                null,
                0,
                null,
                null,
                Instant.ofEpochMilli(1234567000),
                null,
                null,
                null);

        doReturn(runMetadata)
                .when(DEX_ENGINE_MOCK).getRunMetadataById(
                        eq(UUID.fromString("a3c39f8a-0c02-4a8c-8a3a-2f77e203809c")));

        final Response response = jersey
                .target(V1_WORKFLOW + "/token/a3c39f8a-0c02-4a8c-8a3a-2f77e203809c/status")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "token": "a3c39f8a-0c02-4a8c-8a3a-2f77e203809c",
                    "step": "VULN_ANALYSIS",
                    "status": "PENDING"
                  }
                ]
                """);
    }

}
