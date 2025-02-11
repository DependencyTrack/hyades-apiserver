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
import org.dependencytrack.workflow.framework.WorkflowRunStatus;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record WorkflowRunListResponseItem(
        UUID id,
        UUID parentId,
        String workflowName,
        int workflowVersion,
        String status,
        WorkflowRunStatus runtimeStatus,
        String concurrencyGroupId,
        Integer priority,
        Map<String, String> labels,
        @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant createdAt,
        @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant updatedAt,
        @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant startedAt,
        @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT, without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS) Instant completedAt) {
}
