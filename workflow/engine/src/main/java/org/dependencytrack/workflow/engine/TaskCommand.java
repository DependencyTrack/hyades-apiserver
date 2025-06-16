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
package org.dependencytrack.workflow.engine;

import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

sealed interface TaskCommand permits
        TaskCommand.AbandonActivityTaskCommand,
        TaskCommand.CompleteActivityTaskCommand,
        TaskCommand.FailActivityTaskCommand,
        TaskCommand.AbandonWorkflowTaskCommand,
        TaskCommand.CompleteWorkflowTaskCommand {

    record AbandonActivityTaskCommand(ActivityTask task) implements TaskCommand {
    }

    record CompleteActivityTaskCommand(
            ActivityTask task,
            @Nullable WorkflowPayload result,
            Instant timestamp) implements TaskCommand {
    }

    record FailActivityTaskCommand(
            ActivityTask task,
            Throwable exception,
            Instant timestamp) implements TaskCommand {
    }

    record AbandonWorkflowTaskCommand(WorkflowTask task) implements TaskCommand {
    }

    record CompleteWorkflowTaskCommand(WorkflowRunState workflowRunState) implements TaskCommand {
    }

}
