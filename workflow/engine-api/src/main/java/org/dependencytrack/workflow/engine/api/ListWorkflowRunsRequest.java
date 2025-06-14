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
package org.dependencytrack.workflow.engine.api;

import org.jspecify.annotations.Nullable;

import java.util.Map;

public record ListWorkflowRunsRequest(
        @Nullable String nameFilter,
        @Nullable WorkflowRunStatus statusFilter,
        @Nullable Map<String, String> labelFilter,
        @Nullable String pageToken,
        int limit) {

    public ListWorkflowRunsRequest() {
        this(null, null, null, null, 10);
    }

    public ListWorkflowRunsRequest withNameFilter(@Nullable final String nameFilter) {
        return new ListWorkflowRunsRequest(nameFilter, this.statusFilter, this.labelFilter, this.pageToken, this.limit);
    }

    public ListWorkflowRunsRequest withStatusFilter(@Nullable final WorkflowRunStatus statusFilter) {
        return new ListWorkflowRunsRequest(this.nameFilter, statusFilter, this.labelFilter, this.pageToken, this.limit);
    }

    public ListWorkflowRunsRequest withLabelFilter(@Nullable final Map<String, String> labelFilter) {
        return new ListWorkflowRunsRequest(this.nameFilter, this.statusFilter, labelFilter, this.pageToken, this.limit);
    }

    public ListWorkflowRunsRequest withPageToken(@Nullable final String pageToken) {
        return new ListWorkflowRunsRequest(this.nameFilter, this.statusFilter, this.labelFilter, pageToken, this.limit);
    }

    public ListWorkflowRunsRequest withLimit(final int limit) {
        return new ListWorkflowRunsRequest(this.nameFilter, this.statusFilter, this.labelFilter, this.pageToken, limit);
    }

}
