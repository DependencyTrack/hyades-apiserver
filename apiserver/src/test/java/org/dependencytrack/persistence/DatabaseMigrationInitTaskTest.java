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
package org.dependencytrack.persistence;

import alpine.Config;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.init.InitTaskContext;
import org.jdbi.v3.core.Jdbi;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DatabaseMigrationInitTaskTest {

    private PostgreSQLContainer<?> postgresContainer;
    private PGSimpleDataSource dataSource;
    private Jdbi jdbi;

    @Before
    public void setUp() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:13-alpine"));
        postgresContainer.start();

        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        jdbi = Jdbi.create(dataSource);
    }

    @After
    public void tearDown() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void test() throws Exception {
        final var configMock = mock(Config.class);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_URL))).thenReturn(postgresContainer.getJdbcUrl());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_DRIVER))).thenReturn(postgresContainer.getDriverClassName());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_USERNAME))).thenReturn(postgresContainer.getUsername());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_PASSWORD))).thenReturn(postgresContainer.getPassword());
        when(configMock.getPropertyAsBoolean(eq(ConfigKey.INIT_TASKS_ENABLED))).thenReturn(true);

        new DatabaseMigrationInitTask().execute(new InitTaskContext(configMock, dataSource));

        assertMigrationExecuted(/* expectExecuted */ true);
    }

    @Test
    public void testWithMigrationCredentials() throws Exception {
        final var configMock = mock(Config.class);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_URL))).thenReturn(postgresContainer.getJdbcUrl());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_DRIVER))).thenReturn(postgresContainer.getDriverClassName());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_USERNAME))).thenReturn("username");
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_PASSWORD))).thenReturn("password");
        when(configMock.getPropertyAsBoolean(eq(ConfigKey.INIT_TASKS_ENABLED))).thenReturn(true);
        when(configMock.getProperty(eq(ConfigKey.INIT_TASKS_DATABASE_USERNAME))).thenReturn(postgresContainer.getUsername());
        when(configMock.getProperty(eq(ConfigKey.INIT_TASKS_DATABASE_PASSWORD))).thenReturn(postgresContainer.getPassword());

        new DatabaseMigrationInitTask().execute(new InitTaskContext(configMock, dataSource));

        assertMigrationExecuted(/* expectExecuted */ true);
    }

    private void assertMigrationExecuted(final boolean expectExecuted) {
        final List<String> tableNames = jdbi.withHandle(handle -> handle.createQuery("""
                        SELECT "table_name"
                          FROM "information_schema"."tables"
                         WHERE "table_schema" NOT IN ('pg_catalog', 'information_schema')
                        """)
                .mapTo(String.class)
                .list());

        if (expectExecuted) {
            assertThat(tableNames).isNotEmpty();
        } else {
            assertThat(tableNames).isEmpty();
        }
    }

}