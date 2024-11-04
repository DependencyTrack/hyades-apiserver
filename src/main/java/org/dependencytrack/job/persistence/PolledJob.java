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
package org.dependencytrack.job.persistence;

import org.dependencytrack.job.JobStatus;
import org.dependencytrack.proto.job.v1alpha1.JobArgs;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunArgs;

import jakarta.annotation.Nullable;
import java.time.Instant;
import java.util.UUID;

public record PolledJob(
        long id,
        JobStatus status,
        String kind,
        @Nullable Integer priority,
        Instant scheduledFor,
        @Nullable JobArgs arguments,
        @Nullable Long workflowRunId,
        @Nullable UUID workflowRunToken,
        @Nullable Long workflowStepRunId,
        @Nullable WorkflowRunArgs workflowRunArgs,
        Instant createdAt,
        Instant updatedAt,
        Instant startedAt,
        int attempt) {
}
