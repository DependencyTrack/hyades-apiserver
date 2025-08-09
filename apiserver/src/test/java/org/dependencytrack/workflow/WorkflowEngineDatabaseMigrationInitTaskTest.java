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
import org.dependencytrack.init.InitTaskContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_MIGRATION_PASSWORD;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_MIGRATION_URL;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_MIGRATION_USERNAME;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_PASSWORD;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_URL;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_DATABASE_USERNAME;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_ENGINE_ENABLED;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class WorkflowEngineDatabaseMigrationInitTaskTest {

    private PostgreSQLContainer<?> postgresContainer;
    private PGSimpleDataSource dataSource;

    @Before
    public void beforeEach() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:13-alpine"));
        postgresContainer.start();

        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
    }

    @After
    public void afterEach() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void shouldNotExecuteWhenWorkflowEngineIsDisabled() throws Exception {
        final var configMock = mock(Config.class);
        doReturn(false).when(configMock).getPropertyAsBoolean(eq(WORKFLOW_ENGINE_ENABLED));

        new WorkflowEngineDatabaseMigrationInitTask().execute(new InitTaskContext(configMock, dataSource));

        assertMigrationExecuted(false);
    }

    @Test
    public void shouldUseEngineMigrationDataSourceWhenConfigured() throws Exception {
        final var configMock = mock(Config.class);
        doReturn(true).when(configMock).getPropertyAsBoolean(eq(WORKFLOW_ENGINE_ENABLED));
        doReturn(postgresContainer.getJdbcUrl()).when(configMock).getProperty(eq(WORKFLOW_ENGINE_DATABASE_MIGRATION_URL));
        doReturn(postgresContainer.getUsername()).when(configMock).getProperty(eq(WORKFLOW_ENGINE_DATABASE_MIGRATION_USERNAME));
        doReturn(postgresContainer.getPassword()).when(configMock).getProperty(eq(WORKFLOW_ENGINE_DATABASE_MIGRATION_PASSWORD));

        new WorkflowEngineDatabaseMigrationInitTask().execute(new InitTaskContext(configMock, null));

        assertMigrationExecuted(true);
    }

    @Test
    public void shouldUseEngineDataSourceWhenConfigured() throws Exception {
        final var configMock = mock(Config.class);
        doReturn(true).when(configMock).getPropertyAsBoolean(eq(WORKFLOW_ENGINE_ENABLED));
        doReturn(postgresContainer.getJdbcUrl()).when(configMock).getProperty(eq(WORKFLOW_ENGINE_DATABASE_URL));
        doReturn(postgresContainer.getUsername()).when(configMock).getProperty(eq(WORKFLOW_ENGINE_DATABASE_USERNAME));
        doReturn(postgresContainer.getPassword()).when(configMock).getProperty(eq(WORKFLOW_ENGINE_DATABASE_PASSWORD));

        new WorkflowEngineDatabaseMigrationInitTask().execute(new InitTaskContext(configMock, null));

        assertMigrationExecuted(true);
    }

    @Test
    public void shouldUseInitTaskDataSourceAsFallback() throws Exception {
        final var configMock = mock(Config.class);
        doReturn(true).when(configMock).getPropertyAsBoolean(eq(WORKFLOW_ENGINE_ENABLED));

        new WorkflowEngineDatabaseMigrationInitTask().execute(new InitTaskContext(configMock, dataSource));

        assertMigrationExecuted(true);
    }

    private void assertMigrationExecuted(final boolean expectExecuted) throws SQLException {
        try (final Connection connection = postgresContainer.createConnection("");
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT "table_name"
                       FROM "information_schema"."tables"
                      WHERE "table_schema" NOT IN ('pg_catalog', 'information_schema')
                     """)) {
            final ResultSet rs = ps.executeQuery();

            assertThat(rs.next()).isEqualTo(expectExecuted);
        }
    }

}