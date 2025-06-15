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

import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class CreateWorkflowScheduleRequestTest {

    @Test
    void shouldThrowWhenNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new CreateWorkflowScheduleRequest(null, "* * * * *", "workflowName", 1))
                .withMessage("name must not be null");
    }

    @Test
    void shouldThrowWhenCronIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new CreateWorkflowScheduleRequest("name", null, "workflowName", 1))
                .withMessage("cron must not be null");
    }

    @Test
    void shouldThrowWhenCronIsInvalid() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CreateWorkflowScheduleRequest("name", "invalidCron", "workflowName", 1))
                .withMessage("Invalid cron expression: invalidCron");
    }

    @Test
    void shouldThrowWhenWorkflowNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new CreateWorkflowScheduleRequest("name", "* * * * *", null, 1))
                .withMessage("workflowName must not be null");
    }

    @Test
    void shouldPopulateFieldsUsingWithers() {
        final var request = new CreateWorkflowScheduleRequest("name", "* * * * *", "workflowName", 1)
                .withConcurrencyGroupId("concurrencyGroupId")
                .withPriority(666)
                .withLabels(Map.of("foo", "bar"))
                .withArgument(WorkflowPayload.getDefaultInstance())
                .withInitialDelay(Duration.ofMillis(666));

        assertThat(request.name()).isEqualTo("name");
        assertThat(request.cron()).isEqualTo("* * * * *");
        assertThat(request.workflowName()).isEqualTo("workflowName");
        assertThat(request.workflowVersion()).isEqualTo(1);
        assertThat(request.concurrencyGroupId()).isEqualTo("concurrencyGroupId");
        assertThat(request.priority()).isEqualTo(666);
        assertThat(request.labels()).containsEntry("foo", "bar");
        assertThat(request.argument()).isEqualTo(WorkflowPayload.getDefaultInstance());
        assertThat(request.initialDelay()).isEqualTo(Duration.ofMillis(666));
    }

}