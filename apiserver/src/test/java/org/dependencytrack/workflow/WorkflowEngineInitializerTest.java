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

import alpine.Config;
import org.junit.After;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_ENABLED;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class WorkflowEngineInitializerTest {

    private WorkflowEngineInitializer initializer;

    @After
    public void afterEach() {
        if (initializer != null) {
            initializer.contextDestroyed(null);
        }

        WorkflowEngineHolder.set(null);
    }

    @Test
    public void shouldDoNothingWhenEngineIsDisabled() {
        final var configMock = mock(Config.class);
        doReturn(false).when(configMock).getPropertyAsBoolean(eq(WORKFLOW_ENGINE_ENABLED));

        initializer = new WorkflowEngineInitializer(configMock);
        initializer.contextInitialized(null);

        assertThat(WorkflowEngineHolder.get()).isNull();
        assertThat(initializer.getEngine()).isNull();
    }

}