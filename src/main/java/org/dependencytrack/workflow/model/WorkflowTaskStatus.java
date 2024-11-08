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
package org.dependencytrack.workflow.model;

import java.util.Set;

public enum WorkflowTaskStatus {

    PENDING(2),          // 0
    PENDING_RETRY(2),    // 1
    RUNNING(1, 3, 5, 6), // 2
    SUSPENDED(4),        // 3
    PENDING_RESUME(2),   // 4
    COMPLETED,           // 5
    FAILED;              // 6

    private final Set<Integer> allowedTransitions;

    WorkflowTaskStatus(final Integer... allowedTransitions) {
        this.allowedTransitions = Set.of(allowedTransitions);
    }

    boolean canTransitionTo(final WorkflowTaskStatus newState) {
        return allowedTransitions.contains(newState.ordinal());
    }

}
