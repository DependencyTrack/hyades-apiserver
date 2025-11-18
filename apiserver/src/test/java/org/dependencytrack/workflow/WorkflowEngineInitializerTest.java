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

import alpine.test.config.ConfigPropertyRule;
import alpine.test.config.WithConfigProperty;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;

public class WorkflowEngineInitializerTest {

    @Rule
    public final ConfigPropertyRule configPropertyRule = new ConfigPropertyRule();

    private PostgreSQLContainer<?> postgresContainer;
    private WorkflowEngineInitializer initializer;

    @Before
    public void setUp() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:13-alpine"));
        postgresContainer.start();

        configPropertyRule.setProperty("testcontainers.postgresql.jdbc-url", postgresContainer.getJdbcUrl());
        configPropertyRule.setProperty("testcontainers.postgresql.username", postgresContainer.getUsername());
        configPropertyRule.setProperty("testcontainers.postgresql.password", postgresContainer.getPassword());
    }

    @After
    public void afterEach() {
        if (initializer != null) {
            initializer.contextDestroyed(null);
        }
        if (postgresContainer != null) {
            postgresContainer.stop();
        }

        WorkflowEngineHolder.set(null);
    }

    @Test
    @WithConfigProperty("dt.workflow-engine.enabled=false")
    public void shouldDoNothingWhenEngineIsDisabled() {
        initializer = new WorkflowEngineInitializer();
        initializer.contextInitialized(null);

        assertThat(WorkflowEngineHolder.get()).isNull();
        assertThat(initializer.getEngine()).isNull();
    }

    @Test
    @WithConfigProperty(value = {
            "dt.workflow-engine.enabled=true",
            "dt.workflow-engine.database.url=${testcontainers.postgresql.jdbc-url}",
            "dt.workflow-engine.database.username=${testcontainers.postgresql.username}",
            "dt.workflow-engine.database.password=${testcontainers.postgresql.password}"
    })
    public void shouldStartEngine() {
        initializer = new WorkflowEngineInitializer();
        initializer.contextInitialized(null);

        assertThat(WorkflowEngineHolder.get()).isNotNull();
        assertThat(initializer.getEngine()).isNotNull();
        assertThat(initializer.getEngine().probeHealth().getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
    }

}