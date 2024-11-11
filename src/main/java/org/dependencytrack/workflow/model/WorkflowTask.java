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

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;

import java.time.Instant;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public abstract sealed class WorkflowTask permits WorkflowRunTask, WorkflowActivityRunTask {

    private ModelState modelState;
    private UUID id;
    private final String queue;
    private final UUID workflowRunId;
    private WorkflowTaskStatus status;
    private Integer priority;
    private Instant scheduledFor;
    private WorkflowPayload argument;
    private int attempt;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant startedAt;
    private Instant endedAt;

    public WorkflowTask(final UUID workflowRunId, final String queue) {
        this.workflowRunId = requireNonNull(workflowRunId, "workflowRunId must not be null");
        this.id = UUID.randomUUID();
        this.queue = requireNonNull(queue, "queue must not be null");
        this.modelState = ModelState.NEW;
    }

    public void complete(final Instant timestamp) {
        requireNonNull(timestamp, "timestamp must not be null");
        setStatus(WorkflowTaskStatus.COMPLETED);
        this.endedAt = timestamp;
        maybeMarkChanged();
    }

    public void fail(final Instant timestamp, final Instant nextAttemptAt) {
        requireNonNull(timestamp, "timestamp must not be null");
        setStatus(nextAttemptAt != null
                ? WorkflowTaskStatus.PENDING_RETRY
                : WorkflowTaskStatus.FAILED);
        if (nextAttemptAt != null) {
            this.scheduledFor = nextAttemptAt;
        }
        if (this.status == WorkflowTaskStatus.FAILED) {
            this.endedAt = timestamp;
        }
        maybeMarkChanged();
    }

    public ModelState modelState() {
        return modelState;
    }

    void setModelState(final ModelState modelState) {
        this.modelState = requireNonNull(modelState, "state must not be null");
    }

    public UUID id() {
        return id;
    }

    void setId(final UUID id) {
        this.id = requireNonNull(id, "id must not be null");
    }

    public String queue() {
        return queue;
    }

    public UUID workflowRunId() {
        return workflowRunId;
    }

    public WorkflowTaskStatus status() {
        return status;
    }

    public void setStatus(final WorkflowTaskStatus status) {
        requireNonNull(status, "status must not be null");

        if (!this.status.canTransitionTo(status)) {
            throw new IllegalStateException("Can not transition from status %s to %s".formatted(this.status, status));
        }

        this.status = status;
        maybeMarkChanged();
    }

    void setStatusInternal(final WorkflowTaskStatus status) {
        this.status = status;
    }

    public Integer priority() {
        return priority;
    }

    public void setPriority(final Integer priority) {
        this.priority = priority;
        maybeMarkChanged();
    }

    public Instant scheduledFor() {
        return scheduledFor;
    }

    public void setScheduledFor(final Instant scheduledFor) {
        this.scheduledFor = scheduledFor;
        maybeMarkChanged();
    }

    public WorkflowPayload argument() {
        return argument;
    }

    public void setArgument(final WorkflowPayload argument) {
        this.argument = argument;
        maybeMarkChanged();
    }

    public int attempt() {
        return attempt;
    }

    public void setAttempt(final int attempt) {
        this.attempt = attempt;
        maybeMarkChanged();
    }

    public Instant createdAt() {
        return createdAt;
    }

    public void setCreatedAt(final Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant updatedAt() {
        return updatedAt;
    }

    void setUpdatedAt(final Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Instant startedAt() {
        return startedAt;
    }

    void setStartedAt(final Instant startedAt) {
        this.startedAt = startedAt;
    }

    public Instant endedAt() {
        return endedAt;
    }

    void setEndedAt(final Instant endedAt) {
        this.endedAt = endedAt;
    }

    void maybeMarkChanged() {
        if (this.modelState == ModelState.UNCHANGED) {
            this.modelState = ModelState.CHANGED;
        }
    }

}
