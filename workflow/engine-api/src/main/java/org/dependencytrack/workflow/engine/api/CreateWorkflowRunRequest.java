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

import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;

import java.util.Map;

import static java.util.Objects.requireNonNull;

public record CreateWorkflowRunRequest(
        String workflowName,
        int workflowVersion,
        String concurrencyGroupId,
        Integer priority,
        Map<String, String> labels,
        WorkflowPayload argument) {

    public CreateWorkflowRunRequest {
        requireNonNull(workflowName, "workflowName must not be null");
    }

    public CreateWorkflowRunRequest(final String workflowName, final int workflowVersion) {
        this(workflowName, workflowVersion, null, null, null, null);
    }

    public CreateWorkflowRunRequest withConcurrencyGroupId(final String concurrencyGroupId) {
        return new CreateWorkflowRunRequest(this.workflowName, this.workflowVersion,
                concurrencyGroupId, this.priority, this.labels, this.argument);
    }

    public CreateWorkflowRunRequest withPriority(final Integer priority) {
        return new CreateWorkflowRunRequest(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, priority, this.labels, this.argument);
    }

    public CreateWorkflowRunRequest withLabels(final Map<String, String> labels) {
        return new CreateWorkflowRunRequest(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, labels, this.argument);
    }

    public <T> CreateWorkflowRunRequest withArgument(final T argument, final PayloadConverter<T> converter) {
        return new CreateWorkflowRunRequest(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, this.labels, converter.convertToPayload(argument));
    }

}
