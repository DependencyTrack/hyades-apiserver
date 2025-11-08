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
import org.dependencytrack.init.InitTaskContext;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;

public class WorkflowEngineDatabaseMigrationInitTaskTest {

    @Rule
    public final ConfigPropertyRule configPropertyRule = new ConfigPropertyRule();

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

        configPropertyRule.setProperty("testcontainers.postgresql.jdbc-url", postgresContainer.getJdbcUrl());
        configPropertyRule.setProperty("testcontainers.postgresql.username", postgresContainer.getUsername());
        configPropertyRule.setProperty("testcontainers.postgresql.password", postgresContainer.getPassword());
    }

    @After
    public void afterEach() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    @WithConfigProperty("dt.workflow-engine.enabled=false")
    public void shouldNotExecuteWhenWorkflowEngineIsDisabled() throws Exception {
        new WorkflowEngineDatabaseMigrationInitTask().execute(
                new InitTaskContext(ConfigProvider.getConfig(), dataSource));

        assertMigrationExecuted(false);
    }

    @Test
    @WithConfigProperty({
            "dt.workflow-engine.enabled=true",
            "dt.workflow-engine.database.migration-url=${testcontainers.postgresql.jdbc-url}",
            "dt.workflow-engine.database.migration-username=${testcontainers.postgresql.username}",
            "dt.workflow-engine.database.migration-password=${testcontainers.postgresql.password}"
    })
    public void shouldUseEngineMigrationDataSourceWhenConfigured() throws Exception {
        new WorkflowEngineDatabaseMigrationInitTask().execute(
                new InitTaskContext(ConfigProvider.getConfig(), null));

        assertMigrationExecuted(true);
    }

    @Test
    @WithConfigProperty({
            "dt.workflow-engine.enabled=true",
            "dt.workflow-engine.database.url=${testcontainers.postgresql.jdbc-url}",
            "dt.workflow-engine.database.username=${testcontainers.postgresql.username}",
            "dt.workflow-engine.database.password=${testcontainers.postgresql.password}"
    })
    public void shouldUseEngineDataSourceWhenConfigured() throws Exception {
        new WorkflowEngineDatabaseMigrationInitTask().execute(
                new InitTaskContext(ConfigProvider.getConfig(), null));

        assertMigrationExecuted(true);
    }

    @Test
    @WithConfigProperty("dt.workflow-engine.enabled=true")
    public void shouldUseInitTaskDataSourceAsFallback() throws Exception {
        new WorkflowEngineDatabaseMigrationInitTask().execute(
                new InitTaskContext(ConfigProvider.getConfig(), dataSource));

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