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
package org.dependencytrack.workflow.persistence;

import java.time.Instant;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public record NewWorkflowTaskRow(
        UUID id,
        String queue,
        UUID workflowRunId,
        Integer priority,
        Instant scheduledFor,
        UUID activityRunId,
        String activityName,
        String activityInvocationId,
        UUID invokingTaskId,
        String arguments) {

    public NewWorkflowTaskRow(final UUID id, final String queue, final UUID workflowRunId) {
        this(requireNonNull(id, "id must not be null"), requireNonNull(queue, "queue must not be null"),
                requireNonNull(workflowRunId, "workflowRunId must not be null"), null, null, null, null,
                null, null, null);
    }

    public NewWorkflowTaskRow withPriority(final Integer priority) {
        return new NewWorkflowTaskRow(this.id, this.queue, this.workflowRunId, priority, this.scheduledFor,
                this.activityRunId, this.activityName, this.activityInvocationId, this.invokingTaskId, this.arguments);
    }

    public NewWorkflowTaskRow withScheduledFor(final Instant scheduledFor) {
        return new NewWorkflowTaskRow(this.id, this.queue, this.workflowRunId, this.priority, scheduledFor,
                this.activityRunId, this.activityName, this.activityInvocationId, this.invokingTaskId, this.arguments);
    }

    public NewWorkflowTaskRow withActivityRun(
            final UUID activityRunId,
            final String activityName,
            final String activityInvocationId,
            final UUID invokingTaskId) {
        return new NewWorkflowTaskRow(this.id, this.queue, this.workflowRunId, this.priority, this.scheduledFor,
                activityRunId, activityName, activityInvocationId, invokingTaskId, this.arguments);
    }

    public NewWorkflowTaskRow withArguments(final String arguments) {
        return new NewWorkflowTaskRow(this.id, this.queue, this.workflowRunId, this.priority, this.scheduledFor,
                this.activityRunId, this.activityName, this.activityInvocationId, this.invokingTaskId, arguments);
    }

}
