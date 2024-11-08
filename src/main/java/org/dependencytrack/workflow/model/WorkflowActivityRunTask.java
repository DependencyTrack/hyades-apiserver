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
package org.dependencytrack.workflow.model;

import org.dependencytrack.workflow.persistence.WorkflowTaskRow;

import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class WorkflowActivityRunTask extends WorkflowTask {

    private UUID activityRunId;
    private String activityName;
    private String activityInvocationId;
    private UUID invokingTaskId;

    public WorkflowActivityRunTask(
            final UUID workflowRunId,
            final String queue,
            final UUID activityRunId,
            final String activityName,
            final String activityInvocationId,
            final UUID invokingTaskId) {
        super(workflowRunId, queue);
        this.activityRunId = requireNonNull(activityRunId, "activityRunId must not be null");
        this.activityName = requireNonNull(activityName, "activityName must not be null");
        this.activityInvocationId = requireNonNull(activityInvocationId, "activityInvocationId must not be null");
        this.invokingTaskId = requireNonNull(invokingTaskId, "invokingTaskId must not be null");
    }

    public WorkflowActivityRunTask(final WorkflowTaskRow taskRow) {
        super(taskRow.workflowRunId(), taskRow.queue());
        setId(taskRow.id());
        setStatusInternal(taskRow.status());
        setPriority(taskRow.priority());
        setScheduledFor(taskRow.scheduledFor());
        setArguments(taskRow.arguments());
        setResult(taskRow.result());
        setFailureDetails(taskRow.failureDetails());
        setCreatedAt(taskRow.createdAt());
        setUpdatedAt(taskRow.updatedAt());
        setStartedAt(taskRow.startedAt());
        setEndedAt(/* TODO */ null);
        setModelState(ModelState.UNMODIFIED);
    }

    public UUID activityRunId() {
        return activityRunId;
    }

    public String activityName() {
        return activityName;
    }

    public String activityInvocationId() {
        return activityInvocationId;
    }

    public UUID invokingTaskId() {
        return invokingTaskId;
    }

}
