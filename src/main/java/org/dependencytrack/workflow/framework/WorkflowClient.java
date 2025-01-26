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
package org.dependencytrack.workflow.framework;

import org.dependencytrack.workflow.framework.annotation.Workflow;
import org.dependencytrack.workflow.framework.payload.PayloadConverter;

import static java.util.Objects.requireNonNull;

public final class WorkflowClient<A, R> {

    private final String workflowName;
    private final int workflowVersion;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;

    private WorkflowClient(
            final String workflowName,
            final int workflowVersion,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
    }

    public static <A, R, T extends WorkflowExecutor<A, R>> WorkflowClient<A, R> of(
            final Class<T> executorClass,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        requireNonNull(executorClass, "executorClass must not be null");
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");

        final Workflow annotation = executorClass.getAnnotation(Workflow.class);
        if (annotation == null) {
            throw new IllegalArgumentException("Executor class %s is not annotated with %s".formatted(
                    executorClass.getName(), Workflow.class.getName()));
        }

        return new WorkflowClient<>(annotation.name(), annotation.version(), argumentConverter, resultConverter);
    }

    public Awaitable<R> callWithConcurrencyGroupId(
            final WorkflowContext<?, ?> ctx,
            final String concurrencyGroupId,
            final A argument) {
        return ctx.callSubWorkflow(
                this.workflowName,
                this.workflowVersion,
                concurrencyGroupId,
                argument,
                argumentConverter,
                resultConverter);
    }

    // TODO: Add more call variations as needed.

}
