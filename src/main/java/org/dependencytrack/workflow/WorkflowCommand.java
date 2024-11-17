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
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus;

import java.time.Instant;
import java.util.UUID;

sealed interface WorkflowCommand permits
        WorkflowCommand.CompleteExecutionCommand,
        WorkflowCommand.ScheduleActivityTaskCommand,
        WorkflowCommand.ScheduleSubWorkflowCommand,
        WorkflowCommand.ScheduleTimerCommand,
        WorkflowCommand.TerminateExecutionCommand {

    record CompleteExecutionCommand(
            int sequenceId,
            WorkflowRunStatus status,
            WorkflowPayload result,
            String failureDetails) implements WorkflowCommand {
    }

    record ScheduleActivityTaskCommand(
            int sequenceId,
            String name,
            int version,
            Integer priority,
            WorkflowPayload argument) implements WorkflowCommand {
    }

    record ScheduleSubWorkflowCommand(
            int sequenceId,
            String workflowName,
            int workflowVersion,
            Integer priority,
            WorkflowPayload argument) implements WorkflowCommand {
    }

    record ScheduleTimerCommand(
            int sequenceId,
            Instant elapseAt) implements WorkflowCommand {
    }

    record TerminateExecutionCommand(
            int sequenceId,
            UUID instanceId) implements WorkflowCommand {
    }

}
