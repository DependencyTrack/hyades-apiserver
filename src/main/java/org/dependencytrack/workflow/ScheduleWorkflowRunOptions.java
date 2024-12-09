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
package org.dependencytrack.workflow;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.payload.PayloadConverter;

public record ScheduleWorkflowRunOptions(
        String workflowName,
        int workflowVersion,
        String concurrencyGroupId,
        Integer priority,
        WorkflowPayload argument) {

    public ScheduleWorkflowRunOptions(final String workflowName, final int workflowVersion) {
        this(workflowName, workflowVersion, null, null, null);
    }

    public ScheduleWorkflowRunOptions withConcurrencyGroupId(final String concurrencyGroupId) {
        return new ScheduleWorkflowRunOptions(this.workflowName, this.workflowVersion,
                concurrencyGroupId, this.priority, this.argument);
    }

    public ScheduleWorkflowRunOptions withPriority(final Integer priority) {
        return new ScheduleWorkflowRunOptions(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, priority, this.argument);
    }

    public <T> ScheduleWorkflowRunOptions withArgument(final T argument, final PayloadConverter<T> converter) {
        return new ScheduleWorkflowRunOptions(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, converter.convertToPayload(argument));
    }

}
