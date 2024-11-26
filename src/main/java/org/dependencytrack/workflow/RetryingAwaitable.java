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

import org.dependencytrack.workflow.payload.PayloadConverter;

import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

final class RetryingAwaitable<T> extends Awaitable<T> {

    private final Supplier<Awaitable<T>> initialAwaitableSupplier;
    private final Function<RuntimeException, Awaitable<T>> retryAwaitableFunction;

    RetryingAwaitable(
            final WorkflowRunContext<?, ?> executionContext,
            final PayloadConverter<T> resultConverter,
            final Supplier<Awaitable<T>> initialAwaitableSupplier,
            final Function<RuntimeException, Awaitable<T>> retryAwaitableFunction) {
        super(executionContext, resultConverter);
        this.initialAwaitableSupplier = initialAwaitableSupplier;
        this.retryAwaitableFunction = retryAwaitableFunction;
    }

    @Override
    public Optional<T> await() {
        try {
            return initialAwaitableSupplier.get().await();
        } catch (RuntimeException e) {
            if (e instanceof WorkflowRunBlockedException) {
                throw e;
            }

            return retryAwaitableFunction.apply(e).await();
        }
    }

}
