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

import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.dependencytrack.workflow.api.Awaitable;
import org.dependencytrack.workflow.api.failure.CancellationFailureException;
import org.dependencytrack.workflow.api.failure.WorkflowFailureException;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.jspecify.annotations.Nullable;

import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

sealed class AwaitableImpl<T> implements Awaitable<T> permits RetryingAwaitableImpl {

    private final WorkflowContextImpl<?, ?> executionContext;
    private final PayloadConverter<T> resultConverter;
    private boolean completed;
    private boolean canceled;
    @Nullable private String cancelReason;
    @Nullable private Consumer<@Nullable T> completeCallback;
    @Nullable private Consumer<WorkflowFailureException> errorCallback;
    @Nullable private T result;
    @Nullable private WorkflowFailureException exception;

    AwaitableImpl(
            final WorkflowContextImpl<?, ?> workflowContext,
            final PayloadConverter<T> resultConverter) {
        this.executionContext = workflowContext;
        this.resultConverter = resultConverter;
    }

    @Nullable
    @Override
    public T await() {
        do {
            if (completed) {
                if (exception != null) {
                    throw exception;
                } else if (canceled) {
                    throw new CancellationFailureException(cancelReason);
                }

                return result;
            }
        } while (executionContext.processNextEvent() != null);

        throw WorkflowRunBlockedException.INSTANCE;
    }

    boolean complete(@Nullable final WorkflowPayload result) {
        if (completed) {
            return false;
        }

        this.completed = true;
        this.result = resultConverter.convertFromPayload(result);
        if (completeCallback != null) {
            completeCallback.accept(this.result);
        }

        return true;
    }

    boolean completeExceptionally(final WorkflowFailureException exception) {
        if (completed) {
            return false;
        }

        this.completed = true;
        this.exception = exception;
        if (errorCallback != null) {
            errorCallback.accept(this.exception);
        }

        return true;
    }

    boolean cancel(final String reason) {
        requireNonNull(reason, "reason must not be null");

        if (completed) {
            return false;
        }

        this.completed = true;
        this.canceled = true;
        this.cancelReason = reason;

        return true;
    }

    void onComplete(final Consumer<T> callback) {
        this.completeCallback = callback;
    }

    void onError(final Consumer<WorkflowFailureException> callback) {
        this.errorCallback = callback;
    }

}
