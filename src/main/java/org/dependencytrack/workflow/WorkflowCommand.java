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

import java.time.Instant;

sealed interface WorkflowCommand permits
        WorkflowCommand.CancelRunCommand,
        WorkflowCommand.CompleteRunCommand,
        WorkflowCommand.RecordSideEffectResultCommand,
        WorkflowCommand.ScheduleActivityCommand,
        WorkflowCommand.ScheduleSubWorkflowCommand,
        WorkflowCommand.ScheduleTimerCommand {

    record CancelRunCommand(
            int eventId,
            String reason) implements WorkflowCommand {
    }

    record CompleteRunCommand(
            int eventId,
            WorkflowRunStatus status,
            WorkflowPayload result,
            String failureDetails) implements WorkflowCommand {
    }

    record RecordSideEffectResultCommand(
            int eventId,
            WorkflowPayload result) implements WorkflowCommand {
    }

    record ScheduleActivityCommand(
            int eventId,
            String name,
            int version,
            Integer priority,
            WorkflowPayload argument,
            Instant scheduleFor) implements WorkflowCommand {
    }

    record ScheduleSubWorkflowCommand(
            int eventId,
            String workflowName,
            int workflowVersion,
            Integer priority,
            WorkflowPayload argument) implements WorkflowCommand {
    }

    record ScheduleTimerCommand(
            int eventId,
            Instant elapseAt) implements WorkflowCommand {
    }

}
