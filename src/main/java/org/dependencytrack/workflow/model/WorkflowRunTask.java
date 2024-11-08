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

import java.time.Instant;
import java.util.UUID;

public final class WorkflowRunTask extends WorkflowTask {

    public WorkflowRunTask(final UUID workflowRunId, final String queue) {
        super(workflowRunId, queue);
    }

    public WorkflowRunTask(final WorkflowTaskRow taskRow) {
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

    public void suspend(final Instant timestamp) {
        setStatus(WorkflowTaskStatus.SUSPENDED);
        setUpdatedAt(timestamp);
        maybeMarkModified();
    }

    public void resume(final Instant timestamp) {
        setStatus(WorkflowTaskStatus.PENDING_RESUME);
        setUpdatedAt(timestamp);
        maybeMarkModified();
    }

}
