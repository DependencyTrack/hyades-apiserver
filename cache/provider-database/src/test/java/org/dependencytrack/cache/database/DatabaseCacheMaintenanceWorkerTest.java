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
package org.dependencytrack.cache.database;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.support.liquibase.MigrationExecutor;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class DatabaseCacheMaintenanceWorkerTest {

    @Container
    private static final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer("postgres:14-alpine");

    private static DataSourceRegistry dataSourceRegistry;
    private static DataSource dataSource;

    @BeforeAll
    static void beforeAll() throws Exception {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.datasource.default.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.default.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.default.password", postgresContainer.getPassword())))
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);
        dataSource = dataSourceRegistry.getDefault();

        final var migrationExecutor = new MigrationExecutor(
                dataSource, "migration/changelog-main.xml");
        migrationExecutor.executeMigration();
    }

    @AfterEach
    void afterEach() throws Exception {
        try (final Connection connection = dataSource.getConnection();
             final Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE \"CACHE_ENTRY\"");
        }
    }

    @AfterAll
    static void afterAll() {
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
    }

    @Test
    void performMaintenanceShouldDeleteExpiredEntries() throws Exception {
        insertEntry("cache-a", "expired1", "v1", Instant.now().minusSeconds(60), Instant.now().minusSeconds(10));
        insertEntry("cache-a", "expired2", "v2", Instant.now().minusSeconds(60), Instant.now().minusSeconds(5));
        insertEntry("cache-a", "valid", "v3", Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

        try (final var worker = new DatabaseCacheMaintenanceWorker(dataSource, Duration.ofMinutes(1), Duration.ofMinutes(5))) {
            worker.performMaintenance();

            assertThat(countEntries("cache-a")).isEqualTo(1);
            assertThat(entryExists("cache-a", "valid")).isTrue();
        }
    }

    @Test
    void performMaintenanceShouldDeleteExpiredEntriesFromUnregisteredCaches() throws Exception {
        insertEntry("unregistered", "key1", "v1", Instant.now().minusSeconds(60), Instant.now().minusSeconds(10));

        try (final var worker = new DatabaseCacheMaintenanceWorker(dataSource, Duration.ofMinutes(1), Duration.ofMinutes(5))) {
            worker.performMaintenance();

            assertThat(countEntries("unregistered")).isZero();
        }
    }

    @Test
    void performMaintenanceShouldDeleteEntriesExceedingMaxSize() throws Exception {
        for (int i = 1; i <= 5; i++) {
            insertEntry("cache-a", "key" + i, "v" + i,
                    Instant.now().minusSeconds(60 - i),
                    Instant.now().plusSeconds(3600));
        }

        final var cache = new DatabaseCache("cache-a", 3, Duration.ofHours(1), dataSource);

        try (final var worker = new DatabaseCacheMaintenanceWorker(dataSource, Duration.ofMinutes(1), Duration.ofMinutes(5))) {
            worker.registerCache(cache);
            worker.performMaintenance();

            assertThat(countEntries("cache-a")).isEqualTo(3);
            assertThat(entryExists("cache-a", "key1")).isFalse();
            assertThat(entryExists("cache-a", "key2")).isFalse();
            assertThat(entryExists("cache-a", "key3")).isTrue();
            assertThat(entryExists("cache-a", "key4")).isTrue();
            assertThat(entryExists("cache-a", "key5")).isTrue();
        }
    }

    @Test
    void performMaintenanceShouldIncrementEvictionCountForExpiredEntries() throws Exception {
        insertEntry("cache-a", "expired", "v1", Instant.now().minusSeconds(60), Instant.now().minusSeconds(10));

        final var cache = new DatabaseCache("cache-a", 10000, Duration.ofHours(1), dataSource);

        try (final var worker = new DatabaseCacheMaintenanceWorker(dataSource, Duration.ofMinutes(1), Duration.ofMinutes(5))) {
            worker.registerCache(cache);
            worker.performMaintenance();

            assertThat(cache.evictionCount()).isEqualTo(1);
        }
    }

    @Test
    void performMaintenanceShouldIncrementEvictionCountForMaxSizeEvictions() throws Exception {
        for (int i = 1; i <= 5; i++) {
            insertEntry("cache-a", "key" + i, "v" + i,
                    Instant.now().minusSeconds(60 - i),
                    Instant.now().plusSeconds(3600));
        }

        final var cache = new DatabaseCache("cache-a", 2, Duration.ofHours(1), dataSource);

        try (final var worker = new DatabaseCacheMaintenanceWorker(dataSource, Duration.ofMinutes(1), Duration.ofMinutes(5))) {
            worker.registerCache(cache);
            worker.performMaintenance();

            assertThat(cache.evictionCount()).isEqualTo(3);
        }
    }

    @Test
    void performMaintenanceShouldHandleMultipleCaches() throws Exception {
        insertEntry("cache-a", "key1", "v1", Instant.now().minusSeconds(10), Instant.now().plusSeconds(3600));
        insertEntry("cache-a", "key2", "v2", Instant.now().minusSeconds(20), Instant.now().plusSeconds(3600));
        insertEntry("cache-a", "key3", "v3", Instant.now().minusSeconds(30), Instant.now().plusSeconds(3600));

        insertEntry("cache-b", "key1", "v1", Instant.now().minusSeconds(10), Instant.now().plusSeconds(3600));
        insertEntry("cache-b", "key2", "v2", Instant.now().minusSeconds(20), Instant.now().plusSeconds(3600));

        final var cacheA = new DatabaseCache("cache-a", 1, Duration.ofHours(1), dataSource);
        final var cacheB = new DatabaseCache("cache-b", 1, Duration.ofHours(1), dataSource);

        try (final var worker = new DatabaseCacheMaintenanceWorker(dataSource, Duration.ofMinutes(1), Duration.ofMinutes(5))) {
            worker.registerCache(cacheA);
            worker.registerCache(cacheB);
            worker.performMaintenance();

            assertThat(countEntries("cache-a")).isEqualTo(1);
            assertThat(countEntries("cache-b")).isEqualTo(1);
            assertThat(cacheA.evictionCount()).isEqualTo(2);
            assertThat(cacheB.evictionCount()).isEqualTo(1);
        }
    }

    @Test
    void performMaintenanceShouldNotDeleteEntriesWithinMaxSize() throws Exception {
        insertEntry("cache-a", "key1", "v1", Instant.now().minusSeconds(10), Instant.now().plusSeconds(3600));
        insertEntry("cache-a", "key2", "v2", Instant.now().minusSeconds(20), Instant.now().plusSeconds(3600));

        final var cache = new DatabaseCache("cache-a", 10, Duration.ofHours(1), dataSource);

        try (final var worker = new DatabaseCacheMaintenanceWorker(dataSource, Duration.ofMinutes(1), Duration.ofMinutes(5))) {
            worker.registerCache(cache);
            worker.performMaintenance();

            assertThat(countEntries("cache-a")).isEqualTo(2);
            assertThat(cache.evictionCount()).isZero();
        }
    }

    private void insertEntry(
            String cacheName,
            String key,
            String value,
            Instant createdAt,
            Instant expiresAt) throws Exception {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     INSERT INTO "CACHE_ENTRY" ("CACHE_NAME", "KEY", "VALUE", "CREATED_AT", "EXPIRES_AT")
                     VALUES (?, ?, ?, ?, ?)
                     """)) {
            ps.setString(1, cacheName);
            ps.setString(2, key);
            ps.setBytes(3, value.getBytes());
            ps.setTimestamp(4, Timestamp.from(createdAt));
            ps.setTimestamp(5, Timestamp.from(expiresAt));
            ps.executeUpdate();
        }
    }

    private long countEntries(String cacheName) throws Exception {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT COUNT(*) FROM "CACHE_ENTRY" WHERE "CACHE_NAME" = ?
                     """)) {
            ps.setString(1, cacheName);
            final ResultSet rs = ps.executeQuery();
            return rs.next() ? rs.getLong(1) : 0;
        }
    }

    private boolean entryExists(String cacheName, String key) throws Exception {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT 1 FROM "CACHE_ENTRY" WHERE "CACHE_NAME" = ? AND "KEY" = ?
                     """)) {
            ps.setString(1, cacheName);
            ps.setString(2, key);
            return ps.executeQuery().next();
        }
    }

}