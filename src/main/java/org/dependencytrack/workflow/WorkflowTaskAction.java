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

sealed interface WorkflowTaskAction permits
        WorkflowTaskAction.AbandonActivityRunTaskAction,
        WorkflowTaskAction.CompleteActivityRunTaskAction,
        WorkflowTaskAction.AbandonWorkflowRunTaskAction,
        WorkflowTaskAction.CompleteWorkflowRunTaskAction {

    record AbandonActivityRunTaskAction(ActivityRunTask task) implements WorkflowTaskAction {
    }

    record CompleteActivityRunTaskAction(
            ActivityRunTask task,
            WorkflowEvent event) implements WorkflowTaskAction {
    }

    record AbandonWorkflowRunTaskAction(WorkflowRunTask task) implements WorkflowTaskAction {
    }

    record CompleteWorkflowRunTaskAction(WorkflowRun workflowRun) implements WorkflowTaskAction {
    }

}
