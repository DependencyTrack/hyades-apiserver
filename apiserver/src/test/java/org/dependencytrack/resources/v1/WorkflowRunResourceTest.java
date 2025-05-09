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
import org.dependencytrack.workflow.engine.WorkflowEngine;
import org.dependencytrack.workflow.engine.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.persistence.model.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.pagination.Page;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class WorkflowRunResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(WorkflowRunResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(workflowEngineMock).to(WorkflowEngine.class).ranked(666);
                        }
                    }));

    private static final WorkflowEngine workflowEngineMock = mock(WorkflowEngine.class);

    @Test
    public void getWorkflowRunsTest() {
        final var runRow = new WorkflowRunRow(
                UUID.randomUUID(),
                "foo",
                1,
                WorkflowRunStatus.FAILED,
                null,
                null,
                null,
                Map.of("labelName", "labelValue"),
                null,
                null,
                Instant.EPOCH,
                Instant.EPOCH,
                Instant.EPOCH,
                Instant.EPOCH);
        final Page<WorkflowRunRow> runsPage = new Page<>(List.of(runRow), "bmV4dFBhZ2U");

        doReturn(runsPage)
                .when(workflowEngineMock).listRuns(any(ListWorkflowRunsRequest.class));

        final Response response = jersey.target("/v1/workflow/run")
                .queryParam("workflowName", "foo")
                .queryParam("workflowName", "bar")
                .queryParam("status", "FAILED")
                .queryParam("status", "COMPLETED")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getLink("next").getUri()).asString().endsWith("""
                /v1/workflow/run\
                ?pageToken=bmV4dFBhZ2U\
                &pageSize=100\
                &workflowName=foo\
                &workflowName=bar\
                &status=FAILED\
                &status=COMPLETED""");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "id": "${json-unit.any-string}",
                    "workflowName": "foo",
                    "workflowVersion": 1,
                    "status": "FAILED",
                    "labels": {
                      "labelName": "labelValue"
                    }
                  }
                ]
                """);
    }

}