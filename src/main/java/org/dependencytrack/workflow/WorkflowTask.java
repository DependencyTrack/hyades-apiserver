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

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;

import java.util.List;
import java.util.Set;
import java.util.UUID;

record WorkflowTask(
        UUID workflowRunId,
        String workflowName,
        int workflowVersion,
        String concurrencyGroupId,
        Integer priority,
        Set<String> tags,
        int attempt,
        List<WorkflowEvent> eventLog,
        List<WorkflowEvent> inboxEvents) implements Task {

    @Override
    public String taskName() {
        return "%s:%d".formatted(workflowName, workflowVersion);
    }

}
