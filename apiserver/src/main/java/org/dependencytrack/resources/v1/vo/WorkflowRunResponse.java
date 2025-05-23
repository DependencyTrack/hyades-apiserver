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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.resources.v1.serializers.WorkflowFailureSerializer;
import org.dependencytrack.resources.v1.serializers.WorkflowPayloadSerializer;
import org.dependencytrack.workflow.engine.WorkflowRunStateProjection;
import org.dependencytrack.workflow.engine.WorkflowRunStatus;
import org.dependencytrack.workflow.proto.v1.WorkflowFailure;
import org.dependencytrack.workflow.proto.v1.WorkflowPayload;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS;
import static com.fasterxml.jackson.annotation.JsonFormat.Shape.NUMBER_INT;
import static io.swagger.v3.oas.annotations.media.Schema.RequiredMode.REQUIRED;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record WorkflowRunResponse(
        @Schema(requiredMode = REQUIRED) UUID id,
        @Schema(requiredMode = REQUIRED) String workflowName,
        @Schema(requiredMode = REQUIRED) int workflowVersion,
        @JsonSerialize(using = WorkflowPayloadSerializer.class) WorkflowPayload argument,
        @JsonSerialize(using = WorkflowPayloadSerializer.class) WorkflowPayload result,
        @JsonSerialize(using = WorkflowFailureSerializer.class) WorkflowFailure failure,
        @Schema(requiredMode = REQUIRED) WorkflowRunStatus status,
        String customStatus,
        Integer priority,
        Map<String, String> labels,
        @JsonFormat(shape = NUMBER_INT, without = WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) @Schema(requiredMode = REQUIRED) Instant createdAt,
        @JsonFormat(shape = NUMBER_INT, without = WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant updatedAt,
        @JsonFormat(shape = NUMBER_INT, without = WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant startedAt,
        @JsonFormat(shape = NUMBER_INT, without = WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant completedAt) {

        public static WorkflowRunResponse of(final WorkflowRunStateProjection stateProjection) {
                return new WorkflowRunResponse(
                        stateProjection.id(),
                        stateProjection.workflowName(),
                        stateProjection.workflowVersion(),
                        stateProjection.argument(),
                        stateProjection.result(),
                        stateProjection.failure(),
                        stateProjection.status(),
                        stateProjection.customStatus(),
                        stateProjection.priority(),
                        stateProjection.labels(),
                        stateProjection.createdAt(),
                        stateProjection.updatedAt(),
                        stateProjection.startedAt(),
                        stateProjection.completedAt());
        }

}
