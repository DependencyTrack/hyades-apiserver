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
package org.dependencytrack.workflow.persistence.model;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.WorkflowRunStatus;

import jakarta.annotation.Nullable;
import java.time.Instant;
import java.util.UUID;

public record WorkflowRunRow(
        UUID id,
        String workflowName,
        int workflowVersion,
        WorkflowRunStatus status,
        @Nullable String customStatus,
        @Nullable WorkflowPayload argument,
        @Nullable WorkflowPayload result,
        @Nullable String failureDetails,
        @Nullable Integer priority,
        @Nullable String lockedBy,
        @Nullable Instant lockedUntil,
        Instant createdAt,
        @Nullable Instant updatedAt,
        @Nullable Instant completedAt) {
}
