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
import org.dependencytrack.dex.engine.migration.MigrationExecutor;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class DexEngineInitializerTest {

    private PostgreSQLContainer<?> postgresContainer;
    private DataSourceRegistry dataSourceRegistry;
    private DexEngineInitializer initializer;

    @Before
    public void setUp() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:14-alpine"));
        postgresContainer.start();

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        new MigrationExecutor(dataSource).execute();
    }

    @After
    public void afterEach() {
        if (initializer != null) {
            initializer.contextDestroyed(null);
        }
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
        if (postgresContainer != null) {
            postgresContainer.stop();
        }

        DexEngineHolder.set(null);
    }

    @Test
    public void shouldDoNothingWhenEngineIsDisabled() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.dex-engine.enabled", "false")
                .withCustomizers(new DexEngineConfigMappingRegistrar())
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        initializer = new DexEngineInitializer(config, dataSourceRegistry);
        initializer.contextInitialized(null);

        assertThat(DexEngineHolder.get()).isNull();
    }

    @Test
    public void shouldStartEngine() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.dex-engine.enabled", "true"),
                        Map.entry("dt.dex-engine.datasource.name", "foo"),
                        Map.entry("dt.datasource.foo.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.foo.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.foo.password", postgresContainer.getPassword())))
                .withCustomizers(new DexEngineConfigMappingRegistrar())
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        initializer = new DexEngineInitializer(config, dataSourceRegistry);
        initializer.contextInitialized(null);

        assertThat(DexEngineHolder.get()).isNotNull();
        assertThat(DexEngineHolder.get()).isNotNull();
        assertThat(DexEngineHolder.get().probeHealth().getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
    }

}