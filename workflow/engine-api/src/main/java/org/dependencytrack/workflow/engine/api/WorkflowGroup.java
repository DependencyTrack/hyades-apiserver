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
package org.dependencytrack.workflow.engine.api;

import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Workflow;

import java.util.HashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Logical group of workflows to be executed on a shared thread pool.
 *
 * @param name           Name of the group.
 * @param workflowNames  Names of workflows in this group.
 * @param maxConcurrency Number of workflows in this group that can be executed concurrently.
 */
public record WorkflowGroup(String name, Set<String> workflowNames, int maxConcurrency) {

    public WorkflowGroup {
        requireNonNull(name, "name must not be null");
        requireNonNull(workflowNames, "workflowNames must not be null");
        if (maxConcurrency < 1) {
            throw new IllegalArgumentException("maxConcurrency must be greater than 0");
        }
    }

    public WorkflowGroup(final String name) {
        this(name, new HashSet<>(), 1);
    }

    public WorkflowGroup withWorkflow(final String workflowName) {
        final var workflowNames = new HashSet<>(this.workflowNames);
        workflowNames.add(workflowName);
        return new WorkflowGroup(this.name, workflowNames, this.maxConcurrency);
    }

    public WorkflowGroup withWorkflow(final Class<? extends WorkflowExecutor<?, ?>> executorClass) {
        requireNonNull(executorClass, "executorClass must not be null");

        final Workflow workflowAnnotation = executorClass.getAnnotation(Workflow.class);
        if (workflowAnnotation == null) {
            throw new IllegalArgumentException("No @%s annotation found for executor %s".formatted(
                    Workflow.class.getName(), executorClass.getName()));
        }

        return withWorkflow(workflowAnnotation.name());
    }

    public WorkflowGroup withMaxConcurrency(final int maxConcurrency) {
        return new WorkflowGroup(this.name, this.workflowNames, maxConcurrency);
    }

}
