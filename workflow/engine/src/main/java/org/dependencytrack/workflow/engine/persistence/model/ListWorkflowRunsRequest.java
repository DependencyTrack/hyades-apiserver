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
package org.dependencytrack.workflow.engine.persistence.model;

import org.dependencytrack.workflow.engine.WorkflowRunStatus;

import java.util.Collection;
import java.util.Map;

public record ListWorkflowRunsRequest(
        Collection<String> nameFilter,
        Collection<WorkflowRunStatus> statusFilter,
        Map<String, String> labelFilter,
        String pageToken,
        int limit) {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Collection<String> nameFilter;
        private Collection<WorkflowRunStatus> statusFilter;
        private Map<String, String> labelFilter;
        private String pageToken;
        private int limit;

        public Builder nameFilter(final Collection<String> nameFilter) {
            this.nameFilter = nameFilter;
            return this;
        }

        public Builder statusFilter(final Collection<WorkflowRunStatus> statusFilter) {
            this.statusFilter = statusFilter;
            return this;
        }

        public Builder labelFilter(final Map<String, String> labelFilter) {
            this.labelFilter = labelFilter;
            return this;
        }

        public Builder pageToken(final String pageToken) {
            this.pageToken = pageToken;
            return this;
        }

        public Builder limit(final int limit) {
            this.limit = limit;
            return this;
        }

        public ListWorkflowRunsRequest build() {
            return new ListWorkflowRunsRequest(nameFilter, statusFilter, labelFilter, pageToken, limit);
        }

    }

}
