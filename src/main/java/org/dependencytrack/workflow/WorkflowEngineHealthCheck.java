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

import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

@Liveness
public class WorkflowEngineHealthCheck implements HealthCheck {

    private final WorkflowEngine workflowEngine;

    WorkflowEngineHealthCheck(final WorkflowEngine workflowEngine) {
        this.workflowEngine = workflowEngine;
    }

    public WorkflowEngineHealthCheck() {
        this(WorkflowEngine.getInstance());
    }

    @Override
    public HealthCheckResponse call() {
        final WorkflowEngine.State engineState = workflowEngine.state();
        return HealthCheckResponse.named("workflow-engine")
                .status(engineState == WorkflowEngine.State.RUNNING)
                .withData("state", engineState.name())
                .build();
    }

}
