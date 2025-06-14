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
package org.dependencytrack.workflow.engine;

import org.dependencytrack.workflow.api.proto.v1.WorkflowFailure;
import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Projection of a workflow run's state.
 */
public record WorkflowRunStateProjection(
        UUID id,
        String workflowName,
        int workflowVersion,
        @Nullable String concurrencyGroupId,
        @Nullable WorkflowPayload argument,
        @Nullable WorkflowPayload result,
        @Nullable WorkflowFailure failure,
        WorkflowRunStatus status,
        @Nullable String customStatus,
        @Nullable Integer priority,
        @Nullable Map<String, String> labels,
        @Nullable Instant createdAt,
        @Nullable Instant updatedAt,
        @Nullable Instant startedAt,
        @Nullable Instant completedAt) {

    static WorkflowRunStateProjection of(final WorkflowRunState state) {
        return new WorkflowRunStateProjection(
                state.id(),
                state.workflowName(),
                state.workflowVersion(),
                state.concurrencyGroupId().orElse(null),
                state.argument().orElse(null),
                state.result().orElse(null),
                state.failure().orElse(null),
                state.status(),
                state.customStatus().orElse(null),
                state.priority().orElse(null),
                state.labels().orElse(null),
                state.createdAt().orElse(null),
                state.updatedAt().orElse(null),
                state.startedAt().orElse(null),
                state.completedAt().orElse(null));
    }

}
