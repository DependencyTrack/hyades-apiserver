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
package org.dependencytrack.dex.testing;

import com.google.protobuf.DebugFormat;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.DexEngineFactory;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.migration.MigrationExecutor;
import org.jspecify.annotations.Nullable;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public final class WorkflowTestRule implements TestRule {

    private static final DexEngineFactory ENGINE_FACTORY =
            ServiceLoader.load(DexEngineFactory.class).findFirst().orElseThrow();

    private final DataSource dataSource;

    private @Nullable DexEngine engine;

    private @Nullable Consumer<DexEngineConfig> configCustomizer;

    public WorkflowTestRule(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public WorkflowTestRule(final PostgreSQLContainer<?> postgresContainer) {
        this(createDataSource(postgresContainer));
    }

    @Override
    public Statement apply(final Statement statement, final Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                new MigrationExecutor(dataSource).execute();

                final var engineConfig = new DexEngineConfig(UUID.randomUUID(), dataSource);
                engineConfig.setMeterRegistry(new SimpleMeterRegistry());
                if (configCustomizer != null) {
                    configCustomizer.accept(engineConfig);
                }

                engine = ENGINE_FACTORY.create(engineConfig);
                try {
                    statement.evaluate();
                } finally {
                    engine.close();
                    truncateTables(dataSource);
                }
            }
        };
    }

    public DexEngine getEngine() {
        if (engine == null) {
            throw new IllegalStateException("Engine is not initialized yet");
        }

        return engine;
    }

    public WorkflowTestRule withConfigCustomizer(final @Nullable Consumer<DexEngineConfig> configCustomizer) {
        this.configCustomizer = configCustomizer;
        return this;
    }

    public @Nullable WorkflowRun awaitRunStatus(
            final UUID runId,
            final WorkflowRunStatus expectedStatus,
            final Duration timeout) {
        return await("Workflow run status to become " + expectedStatus)
                .atMost(timeout)
                .failFast(() -> {
                    final WorkflowRun run = getEngine().getRun(runId);
                    if (run == null) {
                        return;
                    }

                    assertThat(!expectedStatus.isTerminal() && run.status().isTerminal())
                            .as("If the expected status is non-terminal, the current status must not be terminal")
                            .isFalse();

                    if (expectedStatus.isTerminal() && run.status().isTerminal()) {
                        assertThat(expectedStatus)
                                .as("If expected and actual status are terminal, they must be equal")
                                .withFailMessage(() -> {
                                    var message = "Expected status to be %s, but was %s".formatted(
                                            expectedStatus, run.status());
                                    if (run.failure() != null) {
                                        message += " (failure: %s)".formatted(
                                                DebugFormat.singleLine().toString(run.failure()));
                                    }
                                    return message;
                                })
                                .isEqualTo(run.status());
                    }
                })
                .until(() -> getEngine().getRun(runId), run -> run != null && run.status() == expectedStatus);
    }

    public @Nullable WorkflowRun awaitRunStatus(final UUID runId, final WorkflowRunStatus expectedStatus) {
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(5));
    }

    private static void truncateTables(final DataSource dataSource) {
        try (final Connection connection = dataSource.getConnection();
             final java.sql.Statement statement = connection.createStatement()) {
            statement.execute("""
                    DO $$ DECLARE
                        r RECORD;
                    BEGIN
                        FOR r IN (
                          SELECT tablename
                            FROM pg_tables
                           WHERE schemaname = CURRENT_SCHEMA()
                             AND tablename LIKE 'dex_%'
                             AND tablename NOT LIKE 'dex_engine_schema_%'
                        ) LOOP
                            EXECUTE 'TRUNCATE TABLE ' || QUOTE_IDENT(r.tablename) || ' CASCADE';
                        END LOOP;
                    END $$;
                    """);

            statement.execute("""
                    DO $$
                    DECLARE
                      partition_name TEXT;
                    BEGIN
                      FOR partition_name IN
                        SELECT tablename
                          FROM pg_tables
                         WHERE tablename ~ '^dex_activity_task_q_.+$'
                      LOOP
                        EXECUTE format('DROP TABLE "%s"', partition_name);
                      END LOOP;
                    END $$;
                    """);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to truncate tables", e);
        }
    }

    private static DataSource createDataSource(final PostgreSQLContainer<?> postgresContainer) {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        return dataSource;
    }

}
