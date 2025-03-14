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

import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.payload.PayloadConverter;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.workflow.framework.RetryPolicy.defaultRetryPolicy;

public final class ActivityClient<A, R> {

    private final String activityName;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;

    private ActivityClient(
            final String activityName,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        this.activityName = activityName;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
    }

    public static <A, R, T extends ActivityExecutor<A, R>> ActivityClient<A, R> of(
            final Class<T> executorClass,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        requireNonNull(executorClass, "executorClass must not be null");
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");

        final Activity annotation = executorClass.getAnnotation(Activity.class);
        if (annotation == null) {
            throw new IllegalArgumentException("Executor class %s is not annotated with %s".formatted(
                    executorClass.getName(), Activity.class.getName()));
        }

        return new ActivityClient<>(annotation.name(), argumentConverter, resultConverter);
    }

    public Awaitable<R> call(final WorkflowContext<?, ?> ctx, final A argument, final RetryPolicy retryPolicy) {
        return ctx.callActivity(
                this.activityName,
                argument,
                this.argumentConverter,
                this.resultConverter,
                retryPolicy);
    }

    public Awaitable<R> call(final WorkflowContext<?, ?> ctx, final A argument) {
        return call(ctx, argument, defaultRetryPolicy());
    }

    // TODO: Add more call variations as needed.

}
