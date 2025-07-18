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

import org.jspecify.annotations.Nullable;

public sealed class WorkflowEngineException extends RuntimeException permits
        NonDeterministicWorkflowException,
        WorkflowRunBlockedException,
        WorkflowRunCanceledException,
        WorkflowRunContinuedAsNewException {

    WorkflowEngineException(final String message) {
        super(message);
    }

    WorkflowEngineException(
            @Nullable final String message,
            @Nullable final Throwable cause,
            final boolean enableSuppression,
            final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
