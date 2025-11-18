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

import com.google.protobuf.util.Timestamps;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowRunMetadata;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.proto.event.v1.Event;
import org.dependencytrack.workflow.proto.event.v1.RunCreated;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.stringConverter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

public class WorkflowsResourceTest extends ResourceTest {

    private static final WorkflowEngine WORKFLOW_ENGINE_MOCK = mock(WorkflowEngine.class);

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig()
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(WORKFLOW_ENGINE_MOCK).to(WorkflowEngine.class);
                        }
                    }));

    @After
    @Override
    public void after() {
        reset(WORKFLOW_ENGINE_MOCK);
        super.after();
    }

    @Test
    public void listWorkflowRunsShouldReturnWorkflowRunMetadata() {
        final var workflowRunMetadata = new WorkflowRunMetadata(
                UUID.fromString("724c0700-4eeb-45f0-8ff4-8bba369c0174"),
                "workflowName",
                666,
                WorkflowRunStatus.RUNNING,
                "customStatus",
                123,
                "concurrencyGroupId",
                Map.of("foo", "bar"),
                Instant.ofEpochMilli(666666),
                Instant.ofEpochMilli(777777),
                Instant.ofEpochMilli(888888),
                null);

        doReturn(new Page<>(List.of(workflowRunMetadata), null))
                .when(WORKFLOW_ENGINE_MOCK).listRuns(any(ListWorkflowRunsRequest.class));

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
                              "workflow_version": 666,
                              "status": "RUNNING",
                              "created_at": 666666,
                              "priority": 123,
                              "concurrency_group_id": "concurrencyGroupId",
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
                            }
                          }
                        }
                        """);
    }

    @Test
    public void listWorkflowRunEventsShouldReturnWorkflowRunEvents() {
        final var runId = UUID.fromString("a81df43d-bd7f-4997-9d7a-d735d5101d52");

        final var runMetadata = new WorkflowRunMetadata(
                runId,
                "workflowName",
                666,
                WorkflowRunStatus.CREATED,
                null,
                0,
                null,
                null,
                Instant.ofEpochMilli(666666),
                null,
                null,
                null);

        final var event = Event.newBuilder()
                .setId(1)
                .setTimestamp(Timestamps.fromMillis(666666))
                .setRunCreated(RunCreated.newBuilder()
                        .setWorkflowName("workflowName")
                        .setWorkflowVersion(123)
                        .setArgument(stringConverter().convertToPayload("argument"))
                        .build())
                .build();

        doReturn(runMetadata)
                .when(WORKFLOW_ENGINE_MOCK).getRunMetadata(eq(runId));
        doReturn(new Page<>(List.of(event), null))
                .when(WORKFLOW_ENGINE_MOCK).listRunEvents(any(ListWorkflowRunEventsRequest.class));

        final Response response = jersey.target("/workflow-runs/%s/events".formatted(runId)).request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "events": [
                            {
                              "id": 1,
                              "timestamp": "1970-01-01T00:11:06.666Z",
                              "runCreated": {
                                "workflowName": "workflowName",
                                "workflowVersion": 123,
                                "argument": {
                                  "binaryContent": {
                                    "mediaType": "text/plain",
                                    "data": "YXJndW1lbnQ="
                                  }
                                }
                              }
                            }
                          ],
                          "_pagination": {
                            "links": {
                              "self": "${json-unit.any-string}"
                            }
                          }
                        }
                        """);
    }

    @Test
    public void listWorkflowRunEventsShouldReturnNotFoundWhenRunDoesNotExist() {
        doReturn(null)
                .when(WORKFLOW_ENGINE_MOCK).getRunMetadata(any(UUID.class));

        final Response response = jersey.target("/workflow-runs/a81df43d-bd7f-4997-9d7a-d735d5101d52/events").request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status":404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

}