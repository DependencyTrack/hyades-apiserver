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
package org.dependencytrack.workflow.api.failure;

import org.jspecify.annotations.Nullable;

import java.util.UUID;

/**
 * A {@link FailureException} thrown by the engine when a child workflow failed.
 * <p>
 * Application code must never throw this exception.
 */
public final class ChildWorkflowFailureException extends FailureException {

    private final UUID runId;
    private final String workflowName;
    private final int workflowVersion;

    public ChildWorkflowFailureException(
            final UUID runId,
            final String workflowName,
            final int workflowVersion,
            final @Nullable Throwable cause) {
        super("Run %s of child workflow %s v%d failed".formatted(runId, workflowName, workflowVersion), null, cause);
        this.runId = runId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
    }

    public UUID getRunId() {
        return runId;
    }

    public String getWorkflowName() {
        return workflowName;
    }

    public int getWorkflowVersion() {
        return workflowVersion;
    }

}
