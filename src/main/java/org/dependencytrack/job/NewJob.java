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
package org.dependencytrack.job;

import org.dependencytrack.proto.job.v1alpha1.JobArguments;

import java.time.Instant;
import java.util.Objects;

public record NewJob(
        String kind,
        Integer priority,
        Instant scheduledFor,
        JobArguments arguments,
        Long workflowStepRunId) {

    public NewJob(final String kind) {
        this(Objects.requireNonNull(kind, "kind must not be null"), null, null, null, null);
    }

    public NewJob withPriority(final Integer priority) {
        return new NewJob(this.kind, priority, this.scheduledFor, this.arguments, this.workflowStepRunId);
    }

    public NewJob withScheduledFor(final Instant scheduledFor) {
        return new NewJob(this.kind, this.priority, scheduledFor, this.arguments, this.workflowStepRunId);
    }

    public NewJob withArguments(final JobArguments arguments) {
        return new NewJob(this.kind, this.priority, this.scheduledFor, arguments, this.workflowStepRunId);
    }

    public NewJob withWorkflowStepRunId(final Long workflowStepRunId) {
        return new NewJob(this.kind, this.priority, this.scheduledFor, this.arguments, workflowStepRunId);
    }

}
