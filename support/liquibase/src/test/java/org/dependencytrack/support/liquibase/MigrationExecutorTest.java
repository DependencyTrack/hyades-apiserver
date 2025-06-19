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
package org.dependencytrack.support.liquibase;

import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@Testcontainers
class MigrationExecutorTest {

    @Container
    private final PostgreSQLContainer<?> postgresContainer =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:13-alpine"));

    @Test
    void shouldExecuteMigration() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        assertThatNoException()
                .isThrownBy(new MigrationExecutor(dataSource, "changelog.xml")::executeMigration);

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("select id from databasechangelog")) {
            final ResultSet rs = ps.executeQuery();
            assertThat(rs.next()).isTrue();
            assertThat(rs.getString("id")).isEqualTo("1");
        }
    }

    @Test
    void shouldExecuteMigrationWithCustomChangeLogTableName() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        assertThatNoException()
                .isThrownBy(
                        new MigrationExecutor(dataSource, "changelog.xml")
                                .withChangeLogTableName("custom_changelog")
                                .withChangeLogLockTableName("custom_changeloglock")
                                ::executeMigration);

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("select id from custom_changelog")) {
            final ResultSet rs = ps.executeQuery();
            assertThat(rs.next()).isTrue();
            assertThat(rs.getString("id")).isEqualTo("1");
        }
    }

}