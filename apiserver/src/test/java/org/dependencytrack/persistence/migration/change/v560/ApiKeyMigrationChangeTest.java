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
package org.dependencytrack.persistence.migration.change.v560;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.migration.MigrationInitializer.runMigration;

public class ApiKeyMigrationChangeTest {

    private PostgreSQLContainer<?> postgresContainer;

    @Before
    @SuppressWarnings("resource")
    public void setUp() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:13-alpine"))
                .withInitScript("migration/custom/ApiKeyMigrationChangeTest-schema.sql");
        postgresContainer.start();
    }

    @After
    public void tearDown() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void test() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        try (final PreparedStatement ps = dataSource.getConnection().prepareStatement("""
                INSERT INTO "APIKEY" ("APIKEY", "CREATED")
                VALUES ('tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA', NOW())
                """)) {
            ps.execute();
        }

        assertThat(getApiKeys(dataSource.getConnection())).satisfiesExactly(
                apiKey -> {
                    assertThat(apiKey.apiKey()).isEqualTo("tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
                    assertThat(apiKey.comment()).isNull();
                    assertThat(apiKey.created()).isNotNull();
                    assertThat(apiKey.lastUsed()).isNull();
                    assertThat(apiKey.secretHash()).isNull();
                    assertThat(apiKey.publicId()).isNull();
                    assertThat(apiKey.isLegacy()).isFalse();
                }
        );

        runMigration(dataSource, "migration/custom/ApiKeyMigrationChangeTest-changelog.xml");

        assertThat(getApiKeys(dataSource.getConnection())).satisfiesExactly(
                apiKey -> {
                    assertThat(apiKey.apiKey()).isEqualTo("tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
                    assertThat(apiKey.comment()).isNull();
                    assertThat(apiKey.created()).isNotNull();
                    assertThat(apiKey.lastUsed()).isNull();
                    assertThat(apiKey.secretHash()).isEqualTo("69e36a08fecf861b7ac65c7cc799c4b352bfd9c54ed4214d60fa3aba153af25c");
                    assertThat(apiKey.publicId()).isEqualTo("tl3ZW");
                    assertThat(apiKey.isLegacy()).isTrue();
                }
        );
    }

    private record ApiKeyRecord(
            long id,
            String apiKey,
            String comment,
            Timestamp created,
            Timestamp lastUsed,
            String secretHash,
            String publicId,
            boolean isLegacy) {
    }

    private List<ApiKeyRecord> getApiKeys(final Connection connection) throws Exception {
        final var apiKeys = new ArrayList<ApiKeyRecord>();

        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT * FROM "APIKEY"
                """)) {
            final ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                apiKeys.add(new ApiKeyRecord(
                        rs.getLong("ID"),
                        rs.getString("APIKEY"),
                        rs.getString("COMMENT"),
                        rs.getTimestamp("CREATED"),
                        rs.getTimestamp("LAST_USED"),
                        rs.getString("SECRET_HASH"),
                        rs.getString("PUBLIC_ID"),
                        rs.getBoolean("IS_LEGACY")));
            }
        }

        return apiKeys;
    }

}