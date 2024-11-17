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

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.payload.PayloadConverter;

import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.function.Consumer;

public class Awaitable<T> {

    private final WorkflowRunContext<?, ?> executionContext;
    private final PayloadConverter<T> resultConverter;
    private boolean completed;
    private boolean cancelled;
    private Consumer<T> completeCallback;
    private T result;
    private RuntimeException exception;

    Awaitable(
            final WorkflowRunContext<?, ?> executionContext,
            final PayloadConverter<T> resultConverter) {
        this.executionContext = executionContext;
        this.resultConverter = resultConverter;
    }

    public Optional<T> await() {
        do {
            if (completed) {
                if (exception != null) {
                    throw exception;
                } else if (cancelled) {
                    throw new CancellationException();
                }

                return Optional.ofNullable(result);
            }
        } while (executionContext.processNextEvent() != null);

        throw new WorkflowRunBlockedException();
    }

    boolean complete(final WorkflowPayload result) {
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

    boolean completeExceptionally(final RuntimeException exception) {
        if (completed) {
            return false;
        }

        this.completed = true;
        this.exception = exception;
        return true;
    }

    boolean cancel() {
        if (completed) {
            return false;
        }

        this.completed = true;
        this.cancelled = true;
        return true;
    }

    void onComplete(final Consumer<T> callback) {
        this.completeCallback = callback;
    }

}
