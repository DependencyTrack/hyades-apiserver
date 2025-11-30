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
package org.dependencytrack.dex;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.common.datasource.DataSourceRegistry;
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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class DexEngineDatabaseMigrationInitTaskTest {

    private PostgreSQLContainer<?> postgresContainer;
    private PGSimpleDataSource initTaskDataSource;
    private DataSourceRegistry dataSourceRegistry;

    @Before
    public void beforeEach() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:14-alpine"));
        postgresContainer.start();

        initTaskDataSource = new PGSimpleDataSource();
        initTaskDataSource.setUrl(postgresContainer.getJdbcUrl());
        initTaskDataSource.setUser(postgresContainer.getUsername());
        initTaskDataSource.setPassword(postgresContainer.getPassword());
    }

    @After
    public void afterEach() {
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void shouldNotExecuteWhenEngineIsDisabled() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.dex-engine.enabled", "false")
                .withCustomizers(new DexEngineConfigMappingRegistrar())
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        new DexEngineDatabaseMigrationInitTask(dataSourceRegistry)
                .execute(new InitTaskContext(config, initTaskDataSource));

        assertMigrationExecuted(false);
    }

    @Test
    public void shouldUseEngineMigrationDataSourceWhenConfigured() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.datasource.foo.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.foo.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.foo.password", postgresContainer.getPassword()),
                        Map.entry("dt.dex-engine.enabled", "true"),
                        Map.entry("dt.dex-engine.migration.datasource.name", "foo")))
                .withCustomizers(new DexEngineConfigMappingRegistrar())
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        new DexEngineDatabaseMigrationInitTask(dataSourceRegistry)
                .execute(new InitTaskContext(config, null));

        assertMigrationExecuted(true);
    }

    @Test
    public void shouldUseEngineDataSourceWhenConfigured() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.datasource.foo.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.foo.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.foo.password", postgresContainer.getPassword()),
                        Map.entry("dt.dex-engine.enabled", "true"),
                        Map.entry("dt.dex-engine.datasource.name", "foo")))
                .withCustomizers(new DexEngineConfigMappingRegistrar())
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        new DexEngineDatabaseMigrationInitTask(dataSourceRegistry)
                .execute(new InitTaskContext(config, null));

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