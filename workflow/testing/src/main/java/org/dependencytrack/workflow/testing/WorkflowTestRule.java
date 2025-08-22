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
package org.dependencytrack.workflow.testing;

import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowEngineFactory;
import org.dependencytrack.workflow.engine.api.WorkflowRunMetadata;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.migration.MigrationExecutor;
import org.jspecify.annotations.Nullable;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.function.Consumer;

import static org.awaitility.Awaitility.await;

public final class WorkflowTestRule implements TestRule {

    private static final ServiceLoader<WorkflowEngineFactory> ENGINE_FACTORY_LOADER =
            ServiceLoader.load(WorkflowEngineFactory.class);

    @Nullable
    private WorkflowEngine engine;

    @Nullable
    private Consumer<WorkflowEngineConfig> configCustomizer;

    @Override
    public Statement apply(final Statement statement, final Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                // TODO: Support container reuse.
                try (final var postgresContainer = new PostgreSQLContainer<>(
                        DockerImageName.parse("postgres:13-alpine"))) {
                    postgresContainer.start();

                    final var dataSource = new PGSimpleDataSource();
                    dataSource.setUrl(postgresContainer.getJdbcUrl());
                    dataSource.setUser(postgresContainer.getUsername());
                    dataSource.setPassword(postgresContainer.getPassword());

                    new MigrationExecutor(dataSource).executeMigration();

                    final var engineConfig = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);
                    if (configCustomizer != null) {
                        configCustomizer.accept(engineConfig);
                    }

                    final WorkflowEngineFactory engineFactory = ENGINE_FACTORY_LOADER.findFirst().orElseThrow();

                    engine = engineFactory.create(engineConfig);
                    try {
                        statement.evaluate();
                    } finally {
                        engine.close();
                    }
                }
            }
        };
    }

    public WorkflowEngine getEngine() {
        if (engine == null) {
            throw new IllegalStateException("Engine is not initialized yet");
        }

        return engine;
    }

    public WorkflowTestRule withConfigCustomizer(@Nullable final Consumer<WorkflowEngineConfig> configCustomizer) {
        this.configCustomizer = configCustomizer;
        return this;
    }

    public WorkflowRunMetadata awaitRunStatus(
            final UUID runId,
            final WorkflowRunStatus expectedStatus,
            final Duration timeout) {
        return await("Workflow Run Status to become " + expectedStatus)
                .atMost(timeout)
                .failFast(() -> {
                    final WorkflowRunStatus currentStatus = engine.getRunMetadata(runId).status();
                    if (currentStatus.isTerminal() && !expectedStatus.isTerminal()) {
                        return true;
                    }

                    return currentStatus.isTerminal()
                           && expectedStatus.isTerminal()
                           && currentStatus != expectedStatus;
                })
                .until(() -> engine.getRunMetadata(runId), run -> run.status() == expectedStatus);
    }

    public WorkflowRunMetadata awaitRunStatus(final UUID runId, final WorkflowRunStatus expectedStatus) {
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(5));
    }

}
