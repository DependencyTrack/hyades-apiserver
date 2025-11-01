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

import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.proto.event.v1.TimerCreated;
import org.dependencytrack.workflow.proto.event.v1.TimerElapsed;
import org.dependencytrack.workflow.proto.failure.v1.Failure;
import org.dependencytrack.workflow.proto.payload.v1.Payload;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Map;

import static java.util.Objects.requireNonNull;

sealed interface WorkflowCommand {

    record CompleteRunCommand(
            int eventId,
            WorkflowRunStatus status,
            @Nullable String customStatus,
            @Nullable Payload result,
            @Nullable Failure failure) implements WorkflowCommand {

        public CompleteRunCommand {
            requireNonNull(status, "status must not be null");
        }

    }

    record ContinueRunAsNewCommand(
            int eventId,
            @Nullable Payload argument) implements WorkflowCommand {
    }

    record RecordSideEffectResultCommand(
            String name,
            int eventId,
            @Nullable Payload result) implements WorkflowCommand {

        public RecordSideEffectResultCommand {
            requireNonNull(name, "name must not be null");
        }

    }

    record CreateActivityTaskCommand(
            int eventId,
            String name,
            String queueName,
            @Nullable Integer priority,
            @Nullable Payload argument,
            @Nullable Instant scheduleFor) implements WorkflowCommand {

        public CreateActivityTaskCommand {
            requireNonNull(name, "name must not be null");
            requireNonNull(queueName, "queueName must not be null");
        }

    }

    record CreateChildRunCommand(
            int eventId,
            String workflowName,
            int workflowVersion,
            @Nullable String concurrencyGroupId,
            @Nullable Integer priority,
            @Nullable Map<String, String> labels,
            @Nullable Payload argument) implements WorkflowCommand {

        public CreateChildRunCommand {
            requireNonNull(workflowName, "workflowName must not be null");
        }

    }

    /**
     * @param eventId        ID of the {@link TimerCreated} event.
     * @param elapsedEventId ID of the corresponding {@link TimerElapsed} event.
     * @param name           Name of the timer.
     * @param elapseAt       When the timer elapses.
     */
    record CreateTimerCommand(
            int eventId,
            int elapsedEventId,
            String name,
            Instant elapseAt) implements WorkflowCommand {

        public CreateTimerCommand {
            requireNonNull(name, "name must not be null");
            requireNonNull(elapseAt, "elapseAt must not be null");
        }

    }

}
