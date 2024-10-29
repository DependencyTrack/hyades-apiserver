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
package org.dependencytrack.workflow;

import org.jdbi.v3.core.mapper.reflect.JdbiConstructor;

import jakarta.annotation.Nullable;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record WorkflowRunView(
        String workflowName,
        int workflowVersion,
        UUID token,
        @Nullable Integer priority,
        WorkflowRunStatus status,
        Instant createdAt,
        @Nullable Instant updatedAt,
        @Nullable Instant startedAt,
        List<WorkflowStepRunView> steps) {

    @JdbiConstructor
    @SuppressWarnings("unused")
    public WorkflowRunView(
            final String workflowName,
            final int workflowVersion,
            final UUID token,
            final Integer priority,
            final WorkflowRunStatus status,
            final Instant createdAt,
            @Nullable final Instant updatedAt,
            @Nullable final Instant startedAt) {
        this(workflowName, workflowVersion, token, priority, status, createdAt, updatedAt, startedAt, null);
    }

}
