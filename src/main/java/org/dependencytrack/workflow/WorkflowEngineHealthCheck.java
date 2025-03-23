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

import org.dependencytrack.workflow.framework.WorkflowEngine;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Liveness;

import java.util.function.Supplier;

@Liveness
public class WorkflowEngineHealthCheck implements HealthCheck {

    private final Supplier<WorkflowEngine> workflowEngineSupplier;

    WorkflowEngineHealthCheck(final Supplier<WorkflowEngine> workflowEngineSupplier) {
        this.workflowEngineSupplier = workflowEngineSupplier;
    }

    public WorkflowEngineHealthCheck() {
        // NB: Health check can be called before the engine was initialized.
        this(WorkflowEngineInitializer::workflowEngine);
    }

    @Override
    public HealthCheckResponse call() {
        final WorkflowEngine engine = workflowEngineSupplier.get();

        final HealthCheckResponseBuilder responseBuilder = HealthCheckResponse
                .named("workflow-engine")
                .status(engine != null && engine.status() == WorkflowEngine.Status.RUNNING);
        if (engine != null) {
            responseBuilder.withData("internalStatus", engine.status().name());
        }

        return responseBuilder.build();
    }

}