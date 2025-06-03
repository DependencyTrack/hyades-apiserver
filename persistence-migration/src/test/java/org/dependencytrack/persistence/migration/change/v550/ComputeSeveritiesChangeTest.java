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
package org.dependencytrack.persistence.migration.change.v550;

import org.dependencytrack.support.liquibase.MigrationExecutor;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class ComputeSeveritiesChangeTest {

    @Container
    @SuppressWarnings("resource")
    private final PostgreSQLContainer<?> postgresContainer =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:13-alpine"))
                    .withInitScript("org/dependencytrack/persistence/migration/change/ComputeSeveritiesChangeTest-schema.sql");

    @Test
    public void test() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        try (final PreparedStatement ps = dataSource.getConnection().prepareStatement("""
                INSERT INTO "VULNERABILITY" ("CVSSV2VECTOR", "CVSSV3VECTOR", "OWASPRRVECTOR", "SOURCE", "UUID", "VULNID")
                VALUES (?, ?, ?, ?, ?, ?)
                """)) {
            for (int i = 0; i < 550; i++) {
                ps.setString(1, i % 2 == 0 ? "(AV:N/AC:M/Au:S/C:P/I:P/A:P)" : null);
                ps.setString(2, i % 3 == 0 ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" : null);
                ps.setString(3, i % 5 == 0 ? "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)" : null);
                ps.setString(4, "NVD");
                ps.setString(5, UUID.randomUUID().toString());
                ps.setString(6, "CVE-" + i);
                ps.addBatch();
            }

            ps.executeBatch();
        }

        assertThat(hasVulnsWithoutSeverity(dataSource.getConnection())).isTrue();

        new MigrationExecutor(dataSource, "org/dependencytrack/persistence/migration/change/ComputeSeveritiesChangeTest-changelog.xml").executeMigration();

        assertThat(hasVulnsWithoutSeverity(dataSource.getConnection())).isFalse();
    }

    private boolean hasVulnsWithoutSeverity(final Connection connection) throws Exception {
        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT 1
                  FROM "VULNERABILITY"
                 WHERE "VULNERABILITY"."SEVERITY" IS NULL
                """)) {
            return ps.executeQuery().next();
        }
    }

}