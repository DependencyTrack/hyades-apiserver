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
package org.dependencytrack.persistence.migration.change.v530;

import liquibase.database.jvm.JdbcConnection;
import org.dependencytrack.support.liquibase.MigrationExecutor;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.migration.change.v530.RenameForeignKeysChange.getForeignNameMappings;

@Testcontainers
class RenameForeignKeysChangeTest {

    @Container
    @SuppressWarnings("resource")
    private final PostgreSQLContainer<?> postgresContainer =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:13-alpine"))
                    .withInitScript("org/dependencytrack/persistence/migration/change/schema-v5.2.0-postgresql.sql");

    @Test
    void test() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        new MigrationExecutor(dataSource, "org/dependencytrack/persistence/migration/change/RenameForeignKeysChangeTest-changelog.xml").executeMigration();

        assertThat(getForeignNameMappings(new JdbcConnection(dataSource.getConnection()))).isEmpty();
    }
}
