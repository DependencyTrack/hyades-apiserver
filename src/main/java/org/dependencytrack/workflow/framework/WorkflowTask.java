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
package org.dependencytrack.workflow.framework;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Unit of work for the execution of a workflow run.
 *
 * @param workflowRunId      ID of the workflow run.
 * @param workflowName       Name of the workflow.
 * @param workflowVersion    Version of the workflow.
 * @param concurrencyGroupId ID of the workflow's concurrency group. May be {@code null}.
 * @param priority           Priority of the workflow run. May be {@code null}.
 * @param labels             Labels assigned to the workflow run.
 * @param attempt            Number of attempts for execution of this workflow run.
 *                           Equal to the highest number of dequeue attempts across all messages
 *                           in the run's inbox.
 * @param journal            Journal of processed {@link WorkflowEvent}.
 * @param inbox              {@link WorkflowEvent}s in the run's inbox.
 */
record WorkflowTask(
        UUID workflowRunId,
        String workflowName,
        int workflowVersion,
        String concurrencyGroupId,
        Integer priority,
        Map<String, String> labels,
        int attempt,
        List<WorkflowEvent> journal,
        List<WorkflowEvent> inbox) implements Task {
}
