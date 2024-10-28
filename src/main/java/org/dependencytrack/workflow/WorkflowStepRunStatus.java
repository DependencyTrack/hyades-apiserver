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

import java.util.Set;

public enum WorkflowStepRunStatus {

    PENDING(1, 2),    // 0
    RUNNING(2, 3, 4), // 1
    CANCELLED(0),     // 2
    COMPLETED,        // 3
    FAILED(0);        // 4

    private final Set<Integer> allowedTransitions;

    WorkflowStepRunStatus(final Integer... allowedTransitions) {
        this.allowedTransitions = Set.of(allowedTransitions);
    }

    public boolean canTransition(final WorkflowStepRunStatus newStatus) {
        return allowedTransitions.contains(newStatus.ordinal());
    }

}
