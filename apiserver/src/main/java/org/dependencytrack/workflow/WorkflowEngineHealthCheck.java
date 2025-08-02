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

import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineHealthProbeResult;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Readiness;

import java.util.Map;

/**
 * @since 5.7.0
 */
@Readiness
public class WorkflowEngineHealthCheck implements HealthCheck {

    @Override
    public HealthCheckResponse call() {
        final HealthCheckResponseBuilder responseBuilder =
                HealthCheckResponse.named("workflow-engine");

        final WorkflowEngine engine = WorkflowEngineHolder.get();
        if (engine == null) {
            return responseBuilder.down().build();
        }

        final WorkflowEngineHealthProbeResult probeResult = engine.probeHealth();

        for (final Map.Entry<String, String> dataEntry : probeResult.data().entrySet()) {
            responseBuilder.withData(dataEntry.getKey(), dataEntry.getValue());
        }

        return responseBuilder
                .status(probeResult.isUp())
                .build();
    }

}
