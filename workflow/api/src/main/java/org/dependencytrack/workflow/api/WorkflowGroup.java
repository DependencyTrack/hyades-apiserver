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
package org.dependencytrack.workflow.api;

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
    }

    public WorkflowGroup(final String name) {
        this(name, new HashSet<>(), 1);
    }

    public WorkflowGroup withWorkflow(final String workflowName) {
        this.workflowNames.add(workflowName);
        return this;
    }

    public WorkflowGroup withWorkflow(final Class<? extends WorkflowExecutor<?, ?>> activity) {
        final Workflow workflowAnnotation = activity.getAnnotation(Workflow.class);
        this.workflowNames.add(workflowAnnotation.name());
        return this;
    }

    public WorkflowGroup withMaxConcurrency(final int maxConcurrency) {
        if (maxConcurrency < 1) {
            throw new IllegalArgumentException("maxConcurrency must be greater than 0");
        }
        return new WorkflowGroup(this.name, this.workflowNames, maxConcurrency);
    }

}
