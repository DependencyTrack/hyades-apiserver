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

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.persistence.WorkflowRunRow;

import java.time.Instant;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
public final class WorkflowRun {

    private ModelState modelState;
    private final UUID id;
    private final String workflowName;
    private final int workflowVersion;
    private WorkflowRunStatus status;
    private final Integer priority;
    private final UUID uniqueKey;
    private WorkflowPayload result;
    private String failureDetails;
    private final Instant createdAt;
    private Instant updatedAt;
    private Instant startedAt;
    private Instant endedAt;

    public WorkflowRun(final WorkflowRunRow runRow) {
        this.id = runRow.id();
        this.workflowName = runRow.workflowName();
        this.workflowVersion = runRow.workflowVersion();
        this.status = runRow.status();
        this.priority = runRow.priority();
        this.uniqueKey = runRow.uniqueKey();
        this.result = runRow.result();
        this.failureDetails = runRow.failureDetails();
        this.createdAt = runRow.createdAt();
        this.updatedAt = runRow.updatedAt();
        this.startedAt = runRow.startedAt();
        this.endedAt = runRow.endedAt();
        this.modelState = ModelState.UNCHANGED;
    }

    public void start(final Instant timestamp) {
        requireNonNull(timestamp, "timestamp must not be null");
        setStatus(WorkflowRunStatus.RUNNING);
        this.startedAt = timestamp;
        maybeMarkChanged();
    }

    public void complete(final Instant timestamp, final WorkflowPayload result) {
        requireNonNull(timestamp, "timestamp must not be null");
        setStatus(WorkflowRunStatus.COMPLETED);
        this.result = result;
        this.failureDetails = null;
        this.endedAt = timestamp;
        maybeMarkChanged();
    }

    public void fail(final Instant timestamp, final String failureDetails) {
        requireNonNull(timestamp, "timestamp must not be null");
        setStatus(WorkflowRunStatus.FAILED);
        this.result = null;
        this.failureDetails = failureDetails;
        this.endedAt = timestamp;
        maybeMarkChanged();
    }

    @JsonIgnore
    public ModelState modelState() {
        return modelState;
    }

    @JsonGetter("id")
    public UUID id() {
        return id;
    }

    @JsonGetter("workflowName")
    public String workflowName() {
        return workflowName;
    }

    @JsonGetter("workflowVersion")
    public int workflowVersion() {
        return workflowVersion;
    }

    @JsonGetter("status")
    public WorkflowRunStatus status() {
        return status;
    }

    public void setStatus(final WorkflowRunStatus status) {
        requireNonNull(status, "status must not be null");

        if (!this.status.canTransitionTo(status)) {
            throw new IllegalStateException("Can not transition from status %s to %s".formatted(this.status, status));
        }

        this.status = status;
        maybeMarkChanged();
    }

    @JsonGetter("priority")
    public Integer priority() {
        return priority;
    }

    @JsonGetter("uniqueKey")
    public UUID uniqueKey() {
        return uniqueKey;
    }

    @JsonIgnore
    public WorkflowPayload result() {
        return result;
    }

    @JsonGetter("failureDetails")
    public String failureDetails() {
        return failureDetails;
    }

    @JsonGetter("createdAt")
    public Instant createdAt() {
        return createdAt;
    }

    @JsonGetter("updatedAt")
    public Instant updatedAt() {
        return updatedAt;
    }

    @JsonGetter("startedAt")
    public Instant startedAt() {
        return startedAt;
    }

    @JsonGetter("endedAt")
    public Instant endedAt() {
        return endedAt;
    }

    private void maybeMarkChanged() {
        if (this.modelState == ModelState.UNCHANGED) {
            this.modelState = ModelState.CHANGED;
        }
    }

}
