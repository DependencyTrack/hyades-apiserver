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
package org.dependencytrack.workflow.engine.persistence.model;

import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.jdbi.v3.json.Json;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record WorkflowRunMetadataRow(
        UUID id,
        String workflowName,
        int workflowVersion,
        WorkflowRunStatus status,
        @Nullable String customStatus,
        @Nullable String concurrencyGroupId,
        int priority,
        @Nullable @Json Map<String, String> labels,
        @Nullable String lockedBy,
        @Nullable Instant lockedUntil,
        Instant createdAt,
        @Nullable Instant updatedAt,
        @Nullable Instant startedAt,
        @Nullable Instant completedAt) {
}
