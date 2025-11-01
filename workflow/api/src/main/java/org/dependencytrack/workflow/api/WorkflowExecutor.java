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

import org.jspecify.annotations.Nullable;

public interface WorkflowExecutor<A extends @Nullable Object, R extends @Nullable Object> {

    /**
     * Execute the workflow.
     * <p>
     * <strong>This method may be called by multiple threads concurrently and must be thread-safe!</strong>
     *
     * @param ctx      Context of the execution.
     * @param argument Argument of the execution.
     * @return Result of the execution.
     * @throws Exception        When the execution failed.
     * @throws WorkflowRunError When a condition was encountered that should be handled by the engine.
     *                          <strong>Must not</strong> be caught.
     */
    @Nullable
    R execute(WorkflowContext<@Nullable A> ctx, @Nullable A argument) throws Exception;

}
