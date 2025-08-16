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
package org.dependencytrack.workflow.api;

import org.dependencytrack.workflow.api.failure.CancellationFailureException;
import org.dependencytrack.workflow.api.failure.WorkflowFailureException;
import org.jspecify.annotations.Nullable;

/**
 * A deferred result than can be awaited.
 *
 * @param <T> Type of the result.
 */
public interface Awaitable<T> {

    /**
     * @return The result, if any.
     * @throws WorkflowFailureException     If the {@link Awaitable} completed exceptionally.
     * @throws CancellationFailureException When the awaitable was canceled before it could complete.
     */
    @Nullable
    T await();

}
