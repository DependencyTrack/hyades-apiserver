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

import org.assertj.core.api.InstanceOfAssertFactories;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineHealthProbeResult;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.junit.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class WorkflowEngineHealthCheckTest {

    @Test
    public void shouldReportDownWhenEngineIsNull() {
        final var healthCheck = new WorkflowEngineHealthCheck(() -> null);

        final HealthCheckResponse response = healthCheck.call();
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
        assertThat(response.getData()).isNotPresent();
    }

    @Test
    public void shouldReportUpWhenEngineIsUp() {
        final var engineMock = mock(WorkflowEngine.class);
        doReturn(new WorkflowEngineHealthProbeResult(true, Map.of("foo", "bar")))
                .when(engineMock).probeHealth();

        final var healthCheck = new WorkflowEngineHealthCheck(() -> engineMock);

        final HealthCheckResponse response = healthCheck.call();
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
        assertThat(response.getData())
                .get(InstanceOfAssertFactories.MAP)
                .containsOnly(Map.entry("foo", "bar"));
    }

    @Test
    public void shouldReportDownWhenEngineIsDown() {
        final var engineMock = mock(WorkflowEngine.class);
        doReturn(new WorkflowEngineHealthProbeResult(false, Map.of("foo", "bar")))
                .when(engineMock).probeHealth();

        final var healthCheck = new WorkflowEngineHealthCheck(() -> engineMock);

        final HealthCheckResponse response = healthCheck.call();
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
        assertThat(response.getData())
                .get(InstanceOfAssertFactories.MAP)
                .containsOnly(Map.entry("foo", "bar"));
    }

}