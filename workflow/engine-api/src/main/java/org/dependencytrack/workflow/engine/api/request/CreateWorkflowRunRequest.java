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
package org.dependencytrack.workflow.engine.api.request;

import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.jspecify.annotations.Nullable;

import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Request for creating a workflow run.
 *
 * @param workflowName       Name of the workflow. Must be known to the engine.
 * @param workflowVersion    Version of the workflow.
 * @param concurrencyGroupId Concurrency group ID for the run.
 * @param priority           Priority of the run.
 * @param labels             Labels for the run.
 * @param argument           Argument for the run.
 * @param <A>                Type of the workflow argument.
 */
public record CreateWorkflowRunRequest<A>(
        String workflowName,
        int workflowVersion,
        @Nullable String concurrencyGroupId,
        @Nullable Integer priority,
        @Nullable Map<String, String> labels,
        @Nullable A argument) {

    public CreateWorkflowRunRequest {
        requireNonNull(workflowName, "workflowName must not be null");
    }

    public CreateWorkflowRunRequest(final String workflowName, final int workflowVersion) {
        this(workflowName, workflowVersion, null, null, null, null);
    }

    public CreateWorkflowRunRequest(final Class<? extends WorkflowExecutor<A, ?>> executorClass) {
        this(getWorkflowName(executorClass), getWorkflowVersion(executorClass));
    }

    public CreateWorkflowRunRequest<A> withConcurrencyGroupId(@Nullable final String concurrencyGroupId) {
        return new CreateWorkflowRunRequest<>(this.workflowName, this.workflowVersion,
                concurrencyGroupId, this.priority, this.labels, this.argument);
    }

    public CreateWorkflowRunRequest<A> withPriority(@Nullable final Integer priority) {
        return new CreateWorkflowRunRequest<>(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, priority, this.labels, this.argument);
    }

    public CreateWorkflowRunRequest<A> withLabels(@Nullable final Map<String, String> labels) {
        return new CreateWorkflowRunRequest<>(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, labels, this.argument);
    }

    public CreateWorkflowRunRequest<A> withArgument(@Nullable final A argument) {
        return new CreateWorkflowRunRequest<>(this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, this.labels, argument);
    }

    private static String getWorkflowName(final Class<? extends WorkflowExecutor<?, ?>> executorClass) {
        final Workflow annotation = executorClass.getAnnotation(Workflow.class);
        if (annotation == null) {
            throw new IllegalArgumentException("Class %s is not annotated with @%s".formatted(
                    executorClass.getName(), Workflow.class.getName()));
        }

        return annotation.name();
    }

    private static int getWorkflowVersion(final Class<? extends WorkflowExecutor<?, ?>> executorClass) {
        final Workflow annotation = executorClass.getAnnotation(Workflow.class);
        if (annotation == null) {
            throw new IllegalArgumentException("Class %s is not annotated with @%s".formatted(
                    executorClass.getName(), Workflow.class.getName()));
        }

        return annotation.version();
    }

}
