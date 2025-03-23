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

import org.dependencytrack.workflow.framework.payload.PayloadConverter;

public final class ActivityClient<A, R> {

    private final WorkflowContext<?, ?> workflowContext;
    private final String activityName;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;

    ActivityClient(
            final WorkflowContext<?, ?> workflowContext,
            final String activityName,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        this.workflowContext = workflowContext;
        this.activityName = activityName;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
    }

    public Awaitable<R> call(final ActivityCallOptions<A> options) {
        return workflowContext.callActivity(
                this.activityName,
                options.argument(),
                this.argumentConverter,
                this.resultConverter,
                options.retryPolicy());
    }

}
