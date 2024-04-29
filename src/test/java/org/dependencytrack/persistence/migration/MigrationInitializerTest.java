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
package org.dependencytrack.persistence.migration;

import alpine.Config;
import org.dependencytrack.common.ConfigKey;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MigrationInitializerTest {

    private PostgreSQLContainer<?> postgresContainer;

    @Before
    public void setUp() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"));
        postgresContainer.start();
    }

    @After
    public void tearDown() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void test() {
        final var configMock = mock(Config.class);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_URL))).thenReturn(postgresContainer.getJdbcUrl());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_DRIVER))).thenReturn(postgresContainer.getDriverClassName());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_USERNAME))).thenReturn(postgresContainer.getUsername());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_PASSWORD))).thenReturn(postgresContainer.getPassword());
        when(configMock.getPropertyAsBoolean(eq(ConfigKey.DATABASE_RUN_MIGRATIONS))).thenReturn(true);

        new MigrationInitializer(configMock).contextInitialized(null);
    }

    @Test
    public void testWithMigrationCredentials() {
        final var configMock = mock(Config.class);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_URL))).thenReturn(postgresContainer.getJdbcUrl());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_DRIVER))).thenReturn(postgresContainer.getDriverClassName());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_USERNAME))).thenReturn("username");
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_PASSWORD))).thenReturn("password");
        when(configMock.getPropertyAsBoolean(eq(ConfigKey.DATABASE_RUN_MIGRATIONS))).thenReturn(true);
        when(configMock.getProperty(eq(ConfigKey.DATABASE_MIGRATION_USERNAME))).thenReturn(postgresContainer.getUsername());
        when(configMock.getProperty(eq(ConfigKey.DATABASE_MIGRATION_PASSWORD))).thenReturn(postgresContainer.getPassword());

        new MigrationInitializer(configMock).contextInitialized(null);
    }

}
