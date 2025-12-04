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
package org.dependencytrack.dex.engine.api;

import org.dependencytrack.dex.api.WorkflowCallOptions;

import static org.dependencytrack.dex.proto.common.v1.WorkflowRunConcurrencyMode.WORKFLOW_RUN_CONCURRENCY_MODE_EXCLUSIVE;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunConcurrencyMode.WORKFLOW_RUN_CONCURRENCY_MODE_SERIAL;

public enum WorkflowRunConcurrencyMode {

    /**
     * Only a single in-progress run can exist in a concurrency group.
     * A run is considered in-progress if it has a non-terminal state.
     * <p>
     * This mode is useful when runs are created through user or API interactions,
     * and system load must be protected from excessive amounts of runs being created.
     */
    EXCLUSIVE,

    /**
     * Serialize execution on runs in the same concurrency group.
     * Execution order is determined by highest priority and creation time.
     * <p>
     * This is the default and only option for workflows that invoke each other via
     * {@link org.dependencytrack.dex.api.WorkflowHandle#call(WorkflowCallOptions)}.
     */
    SERIAL;

    public org.dependencytrack.dex.proto.common.v1.WorkflowRunConcurrencyMode toProto() {
        return switch (this) {
            case EXCLUSIVE -> WORKFLOW_RUN_CONCURRENCY_MODE_EXCLUSIVE;
            case SERIAL -> WORKFLOW_RUN_CONCURRENCY_MODE_SERIAL;
        };
    }

    public static WorkflowRunConcurrencyMode fromProto(
            final org.dependencytrack.dex.proto.common.v1.WorkflowRunConcurrencyMode protoMode) {
        return switch (protoMode) {
            case WORKFLOW_RUN_CONCURRENCY_MODE_EXCLUSIVE -> WorkflowRunConcurrencyMode.EXCLUSIVE;
            case WORKFLOW_RUN_CONCURRENCY_MODE_SERIAL -> WorkflowRunConcurrencyMode.SERIAL;
            default -> throw new IllegalArgumentException("Unexpected mode: " + protoMode);
        };
    }

}
