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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public interface Awaitable<T> {

    Optional<T> await();

    static Awaitable<Void> allOf(final Awaitable<?>... awaitables) {
        return new All(List.of(awaitables));
    }

    final class Single<T> implements Awaitable<T> {

        private final UUID completionId;
        private boolean completed;
        private RuntimeException exception;
        private T result;

        Single(final UUID completionId) {
            this.completionId = requireNonNull(completionId, "completionId must not be null");
        }

        Single(final UUID completionId, final T result) {
            this.completionId = requireNonNull(completionId, "completionId must not be null");
            this.result = result;
            this.completed = true;
        }

        Single(final UUID completionId, final RuntimeException exception) {
            this.completionId = requireNonNull(completionId, "completionId must not be null");
            ;
            this.exception = requireNonNull(exception, "exception must not be null");
            this.completed = true;
        }

        @Override
        public Optional<T> await() {
            if (!completed) {
                throw new WorkflowRunSuspendedException(completionId);
            }

            if (exception != null) {
                throw exception;
            }

            return Optional.ofNullable(result);
        }

    }

    final class All implements Awaitable<Void> {

        private final List<UUID> completionIds = new ArrayList<>();
        private RuntimeException exception;
        private final boolean completed;

        All(final Collection<Awaitable<?>> awaitables) {
            for (final Awaitable<?> awaitable : awaitables) {
                try {
                    awaitable.await();
                } catch (WorkflowRunSuspendedException e) {
                    completionIds.addAll(e.getAwaitedCompletionIds());
                } catch (RuntimeException e) {
                    exception = e;
                    break;
                }
            }
            completed = completionIds.isEmpty() && exception == null;
        }

        @Override
        public Optional<Void> await() {
            if (!completed) {
                throw new WorkflowRunSuspendedException(completionIds);
            }

            if (exception != null) {
                throw exception;
            }

            return Optional.empty();
        }

    }

}
