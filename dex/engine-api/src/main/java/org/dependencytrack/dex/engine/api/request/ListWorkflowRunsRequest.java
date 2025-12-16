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
package org.dependencytrack.dex.engine.api.request;

import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Map;

public record ListWorkflowRunsRequest(
        @Nullable String workflowName,
        @Nullable Integer workflowVersion,
        @Nullable String workflowInstanceId,
        @Nullable WorkflowRunStatus status,
        @Nullable Map<String, String> labels,
        @Nullable Instant createdAtFrom,
        @Nullable Instant createdAtTo,
        @Nullable Instant completedAtFrom,
        @Nullable Instant completedAtTo,
        @Nullable SortBy sortBy,
        @Nullable SortDirection sortDirection,
        @Nullable String pageToken,
        int limit) {

    public enum SortBy {
        ID,
        CREATED_AT,
        COMPLETED_AT
    }

    public ListWorkflowRunsRequest() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, 10);
    }

    public ListWorkflowRunsRequest withWorkflowName(@Nullable String workflowName) {
        return new ListWorkflowRunsRequest(
                workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withWorkflowVersion(@Nullable Integer workflowVersion) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withWorkflowInstanceId(@Nullable String workflowInstanceId) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withStatus(@Nullable WorkflowRunStatus status) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withLabels(@Nullable Map<String, String> labelFilter) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                labelFilter,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCreatedAtFrom(@Nullable Instant createdAtFrom) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCreatedAtTo(@Nullable Instant createdAtTo) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCompletedAtFrom(@Nullable Instant completedAtFrom) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCompletedAtTo(@Nullable Instant completedAtTo) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withPageToken(@Nullable String pageToken) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withLimit(int limit) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                limit);
    }

    public ListWorkflowRunsRequest withSortBy(@Nullable SortBy sortBy) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withSortDirection(@Nullable SortDirection sortDirection) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.status,
                this.labels,
                this.createdAtFrom,
                this.createdAtTo,
                this.completedAtFrom,
                this.completedAtTo,
                this.sortBy,
                sortDirection,
                this.pageToken,
                this.limit);
    }

}
