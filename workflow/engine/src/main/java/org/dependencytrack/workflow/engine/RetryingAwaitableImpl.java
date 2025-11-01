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

import org.dependencytrack.workflow.api.failure.FailureException;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.jspecify.annotations.Nullable;

import java.util.function.Function;

import static java.util.Objects.requireNonNull;

final class RetryingAwaitableImpl<T> extends AwaitableImpl<T> {

    private final AwaitableImpl<T> initialAwaitable;
    private final Function<FailureException, AwaitableImpl<T>> retryAwaitableFunction;

    RetryingAwaitableImpl(
            final WorkflowContextImpl<?, ?> workflowContext,
            final PayloadConverter<T> resultConverter,
            final AwaitableImpl<T> initialAwaitable,
            final Function<FailureException, AwaitableImpl<T>> retryAwaitableFunction) {
        super(workflowContext, resultConverter);
        this.initialAwaitable = requireNonNull(initialAwaitable, "initialAwaitable must not be null");
        this.retryAwaitableFunction = requireNonNull(retryAwaitableFunction, "retryAwaitableFunction must not be null");
    }

    @Override
    public @Nullable T await() {
        try {
            return initialAwaitable.await();
        } catch (FailureException e) {
            return retryAwaitableFunction.apply(e).await();
        }
    }

}
