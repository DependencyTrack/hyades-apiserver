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

import org.dependencytrack.workflow.persistence.WorkflowRunRow;

import java.time.Instant;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class WorkflowRun {

    private ModelState modelState;
    private final UUID id;
    private final String workflowName;
    private final int workflowVersion;
    private WorkflowRunStatus status;
    private Integer priority;
    private String result;
    private String failureDetails;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant startedAt;
    private Instant endedAt;

    public WorkflowRun(final String workflowName, final int workflowVersion, final UUID runId) {
        this.id = runId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.modelState = ModelState.NEW;
    }

    public WorkflowRun(final WorkflowRunRow runRow) {
        this.id = runRow.id();
        this.workflowName = runRow.workflowName();
        this.workflowVersion = runRow.workflowVersion();
        this.status = runRow.status();
        this.result = runRow.result();
        this.failureDetails = runRow.failureDetails();
        this.createdAt = runRow.createdAt();
        this.updatedAt = runRow.updatedAt();
        this.startedAt = runRow.startedAt();
        this.endedAt = runRow.endedAt();
        this.modelState = ModelState.UNMODIFIED;
    }

    public void start(final Instant timestamp) {
        setStatus(WorkflowRunStatus.RUNNING);
        this.startedAt = timestamp;
        this.updatedAt = timestamp;
        maybeMarkModified();
    }

    public void complete(final Instant timestamp, final String result) {
        setStatus(WorkflowRunStatus.COMPLETED);
        this.result = result;
        this.failureDetails = null;
        this.updatedAt = timestamp;
        this.endedAt = timestamp;
        maybeMarkModified();
    }

    public void fail(final Instant timestamp, final String failureDetails) {
        setStatus(WorkflowRunStatus.FAILED);
        this.result = null;
        this.failureDetails = failureDetails;
        this.updatedAt = timestamp;
        this.endedAt = timestamp;
        maybeMarkModified();
    }

    public ModelState modelState() {
        return modelState;
    }

    public UUID id() {
        return id;
    }

    public String workflowName() {
        return workflowName;
    }

    public int workflowVersion() {
        return workflowVersion;
    }

    public WorkflowRunStatus status() {
        return status;
    }

    public void setStatus(final WorkflowRunStatus status) {
        requireNonNull(status, "status must not be null");

        if (!this.status.canTransitionTo(status)) {
            throw new IllegalStateException("Can not transition from status %s to %s".formatted(this.status, status));
        }

        this.status = status;
        maybeMarkModified();
    }

    public Integer priority() {
        return priority;
    }

    public void setPriority(final Integer priority) {
        this.priority = priority;
        maybeMarkModified();
    }

    public String result() {
        return result;
    }

    public String failureDetails() {
        return failureDetails;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public void setCreatedAt(final Instant createdAt) {
        this.createdAt = createdAt;
        maybeMarkModified();
    }

    public Instant updatedAt() {
        return updatedAt;
    }

    public Instant startedAt() {
        return startedAt;
    }

    public Instant endedAt() {
        return endedAt;
    }

    private void maybeMarkModified() {
        if (this.modelState == ModelState.UNMODIFIED) {
            this.modelState = ModelState.MODIFIED;
        }
    }

}
