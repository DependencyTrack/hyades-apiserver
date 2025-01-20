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

    public static <A, R, T extends ActivityRunner<A, R>> ActivityClient<A, R> of(
            final Class<T> runnerClass,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        requireNonNull(runnerClass, "runnerClass must not be null");
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");

        final Activity annotation = runnerClass.getAnnotation(Activity.class);
        if (annotation == null) {
            throw new IllegalArgumentException("Runner class %s is not annotated with %s".formatted(
                    runnerClass.getName(), Activity.class.getName()));
        }

        return new ActivityClient<>(annotation.name(), argumentConverter, resultConverter);
    }

    public Awaitable<R> call(final WorkflowRunContext<?, ?> ctx, final A argument, final RetryPolicy retryPolicy) {
        return ctx.callActivity(
                this.activityName,
                argument,
                this.argumentConverter,
                this.resultConverter,
                retryPolicy);
    }

    // TODO: Add more call variations as needed.

}
