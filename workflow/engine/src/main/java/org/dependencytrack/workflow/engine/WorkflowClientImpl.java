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

import org.dependencytrack.workflow.Awaitable;
import org.dependencytrack.workflow.WorkflowCallOptions;
import org.dependencytrack.workflow.WorkflowClient;
import org.dependencytrack.workflow.payload.PayloadConverter;

import static java.util.Objects.requireNonNull;

final class WorkflowClientImpl<A, R> implements WorkflowClient<A, R> {

    private final WorkflowContextImpl<?, ?> workflowContext;
    private final String workflowName;
    private final int workflowVersion;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;

    WorkflowClientImpl(
            final WorkflowContextImpl<?, ?> workflowContext,
            final String workflowName,
            final int workflowVersion,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        this.workflowContext = requireNonNull(workflowContext);
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
    }

    @Override
    public Awaitable<R> call(final WorkflowCallOptions<A> options) {
        return workflowContext.callSubWorkflow(
                this.workflowName,
                this.workflowVersion,
                options.concurrencyGroupId(),
                options.argument(),
                argumentConverter,
                resultConverter);
    }

}
