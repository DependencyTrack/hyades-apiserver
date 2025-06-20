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
package org.dependencytrack.workflow.engine.api.request;

import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ListWorkflowRunsRequestTest {

    @Test
    void shouldPopulateFieldsUsingWithers() {
        final var request = new ListWorkflowRunsRequest()
                .withWorkflowNameFilter("workflowName")
                .withWorkflowVersionFilter(123)
                .withStatusFilter(WorkflowRunStatus.RUNNING)
                .withLabelFilter(Map.of("foo", "bar"))
                .withCreatedAtFrom(Instant.ofEpochSecond(111))
                .withCreatedAtTo(Instant.ofEpochSecond(222))
                .withCompletedAtFrom(Instant.ofEpochSecond(333))
                .withCompletedAtTo(Instant.ofEpochSecond(444))
                .withPageToken("pageToken")
                .withLimit(666);

        assertThat(request.workflowNameFilter()).isEqualTo("workflowName");
        assertThat(request.workflowVersionFilter()).isEqualTo(123);
        assertThat(request.statusFilter()).isEqualTo(WorkflowRunStatus.RUNNING);
        assertThat(request.labelFilter()).containsEntry("foo", "bar");
        assertThat(request.createdAtFrom()).isEqualTo(Instant.ofEpochSecond(111));
        assertThat(request.createdAtTo()).isEqualTo(Instant.ofEpochSecond(222));
        assertThat(request.completedAtFrom()).isEqualTo(Instant.ofEpochSecond(333));
        assertThat(request.completedAtTo()).isEqualTo(Instant.ofEpochSecond(444));
        assertThat(request.pageToken()).isEqualTo("pageToken");
        assertThat(request.limit()).isEqualTo(666);
    }

}