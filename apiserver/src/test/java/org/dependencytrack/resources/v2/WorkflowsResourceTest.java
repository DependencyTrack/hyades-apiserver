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
package org.dependencytrack.resources.v2;

import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class WorkflowsResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
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
    public void listWorkflowRunsShouldReturnWorkflowRunMetadata() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var workflowRunMetadata = new WorkflowRunMetadata(
                UUID.fromString("724c0700-4eeb-45f0-8ff4-8bba369c0174"),
                "workflowName",
                66,
                "workflowInstanceId",
                WorkflowRunStatus.RUNNING,
                "customStatus",
                12,
                "concurrencyKey",
                Map.of("foo", "bar"),
                Instant.ofEpochMilli(666666),
                Instant.ofEpochMilli(777777),
                Instant.ofEpochMilli(888888),
                null);

        doReturn(new Page<>(List.of(workflowRunMetadata), null).withTotalCount(1, TotalCount.Type.EXACT))
                .when(DEX_ENGINE_MOCK).listRuns(any(ListWorkflowRunsRequest.class));

        final Response response = jersey.target("/workflow-runs").request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "workflow_runs": [
                            {
                              "id": "724c0700-4eeb-45f0-8ff4-8bba369c0174",
                              "workflow_name": "workflowName",
                              "workflow_version": 66,
                              "workflow_instance_id": "workflowInstanceId",
                              "status": "RUNNING",
                              "created_at": 666666,
                              "priority": 12,
                              "concurrency_key": "concurrencyKey",
                              "labels": {
                                "foo": "bar"
                              },
                              "updated_at": 777777,
                              "started_at": 888888
                            }
                          ],
                          "_pagination": {
                            "links": {
                              "self": "${json-unit.any-string}"
                            },
                            "total": {
                              "count": 1,
                              "type": "EXACT"
                            }
                          }
                        }
                        """);
    }

    @Test
    public void listWorkflowRunsShouldPassQueryParametersToDexEngine() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        doReturn(Page.empty())
                .when(DEX_ENGINE_MOCK).listRuns(any(ListWorkflowRunsRequest.class));

        final Response response = jersey.target("/workflow-runs")
                .queryParam("workflow_name", "testWorkflow")
                .queryParam("workflow_version", 42)
                .queryParam("workflow_instance_id", "instance-123")
                .queryParam("status", "CANCELLED")
                .queryParam("created_at_from", 1000000)
                .queryParam("created_at_to", 2000000)
                .queryParam("completed_at_from", 3000000)
                .queryParam("completed_at_to", 4000000)
                .queryParam("limit", 50)
                .queryParam("page_token", "nextPageToken")
                .queryParam("sort_direction", "DESC")
                .queryParam("sort_by", "created_at")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);

        final var requestCaptor = ArgumentCaptor.forClass(ListWorkflowRunsRequest.class);
        verify(DEX_ENGINE_MOCK).listRuns(requestCaptor.capture());

        final ListWorkflowRunsRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.workflowName()).isEqualTo("testWorkflow");
        assertThat(capturedRequest.workflowVersion()).isEqualTo(42);
        assertThat(capturedRequest.workflowInstanceId()).isEqualTo("instance-123");
        assertThat(capturedRequest.status()).isEqualTo(WorkflowRunStatus.CANCELED);
        assertThat(capturedRequest.createdAtFrom()).isEqualTo(Instant.ofEpochMilli(1000000));
        assertThat(capturedRequest.createdAtTo()).isEqualTo(Instant.ofEpochMilli(2000000));
        assertThat(capturedRequest.completedAtFrom()).isEqualTo(Instant.ofEpochMilli(3000000));
        assertThat(capturedRequest.completedAtTo()).isEqualTo(Instant.ofEpochMilli(4000000));
        assertThat(capturedRequest.limit()).isEqualTo(50);
        assertThat(capturedRequest.pageToken()).isEqualTo("nextPageToken");
        assertThat(capturedRequest.sortDirection()).isEqualTo(SortDirection.DESC);
        assertThat(capturedRequest.sortBy()).isEqualTo(ListWorkflowRunsRequest.SortBy.CREATED_AT);
    }

}