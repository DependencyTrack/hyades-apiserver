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

import org.dependencytrack.workflow.persistence.PolledWorkflowTaskRow;

import java.util.Optional;
import java.util.OptionalInt;
import java.util.UUID;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

public abstract sealed class WorkflowTaskContext<A> permits WorkflowRunContext, WorkflowActivityContext {

    @FunctionalInterface
    interface Factory<A, C extends WorkflowTaskContext<A>> extends Function<PolledWorkflowTaskRow, C> {
    }

    // TODO: workflowName, workflowVersion
    private final UUID taskId;
    private final String taskQueue;
    private final Integer taskPriority;
    private final UUID runId;
    private final A arguments;

    WorkflowTaskContext(
            final UUID taskId,
            final String taskQueue,
            final Integer taskPriority,
            final UUID runId,
            final A arguments) {
        this.taskId = taskId;
        this.taskQueue = requireNonNull(taskQueue);
        this.taskPriority = taskPriority;
        this.runId = requireNonNull(runId);
        this.arguments = arguments;
    }

    public UUID taskId() {
        return taskId;
    }

    public String taskQueue() {
        return taskQueue;
    }

    public OptionalInt taskPriority() {
        if (taskPriority == null) {
            return OptionalInt.empty();
        }

        return OptionalInt.of(taskPriority);
    }

    public UUID runId() {
        return runId;
    }

    public Optional<A> arguments() {
        return Optional.ofNullable(arguments);
    }

}
