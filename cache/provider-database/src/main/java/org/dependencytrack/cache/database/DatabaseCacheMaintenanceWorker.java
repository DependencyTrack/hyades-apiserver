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

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.Closeable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @since 5.7.0
 */
final class DatabaseCacheMaintenanceWorker implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseCacheMaintenanceWorker.class);

    private final DataSource dataSource;
    private final Duration initialDelay;
    private final Duration interval;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Map<String, DatabaseCache> cacheByName;
    private @Nullable ScheduledExecutorService executor;

    DatabaseCacheMaintenanceWorker(
            DataSource dataSource,
            Duration initialDelay,
            Duration interval) {
        this.dataSource = dataSource;
        this.initialDelay = initialDelay;
        this.interval = interval;
        this.cacheByName = new ConcurrentHashMap<>();
    }

    void start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("Already started");
        }

        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name(getClass().getSimpleName(), 0)
                        .factory());
        executor.scheduleAtFixedRate(
                () -> {
                    try {
                        performMaintenance();
                    } catch (SQLException | RuntimeException e) {
                        LOGGER.error("Failed to perform cache maintenance", e);
                    }
                },
                initialDelay.toMillis(),
                interval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    void registerCache(DatabaseCache cache) {
        LOGGER.debug("Registering cache '{}'", cache.name());
        cacheByName.putIfAbsent(cache.name(), cache);
    }

    void performMaintenance() throws SQLException {
        LOGGER.debug("Starting cache maintenance");

        final var cacheNames = new ArrayList<String>(cacheByName.size());
        final var maxSizes = new ArrayList<Integer>(cacheByName.size());

        for (final var entry : cacheByName.entrySet()) {
            cacheNames.add(entry.getKey());
            maxSizes.add(entry.getValue().maxSize());
        }

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement expireQuery = connection.prepareStatement("""
                     WITH cte_expired AS (
                       DELETE
                         FROM "CACHE_ENTRY"
                        WHERE "EXPIRES_AT" < NOW()
                       RETURNING "CACHE_NAME"
                     )
                     SELECT "CACHE_NAME"
                          , COUNT(*)
                       FROM cte_expired
                      GROUP BY "CACHE_NAME"
                     """);
             final PreparedStatement maxSizeQuery = connection.prepareStatement("""
                     WITH
                     cte_input AS (
                       SELECT cache_name
                            , max_size
                         FROM UNNEST(?, ?)
                           AS t(cache_name, max_size)
                     )
                     , cte_ranked AS (
                       SELECT ce."CACHE_NAME"
                            , ce."KEY"
                            , ROW_NUMBER() OVER (PARTITION BY ce."CACHE_NAME" ORDER BY ce."CREATED_AT" DESC) AS rn
                            , i.max_size
                         FROM "CACHE_ENTRY" AS ce
                        INNER JOIN cte_input AS i
                           ON i.cache_name = ce."CACHE_NAME"
                     )
                     , cte_deleted AS (
                       DELETE
                         FROM "CACHE_ENTRY"
                        WHERE ("CACHE_NAME", "KEY") IN (
                          SELECT "CACHE_NAME"
                               , "KEY"
                            FROM cte_ranked
                           WHERE cte_ranked.rn > cte_ranked.max_size
                        )
                       RETURNING "CACHE_NAME"
                     )
                     SELECT "CACHE_NAME"
                          , COUNT(*)
                       FROM cte_deleted
                      GROUP BY "CACHE_NAME"
                     """)) {
            try (final ResultSet rs = expireQuery.executeQuery()) {
                while (rs.next()) {
                    final String cacheName = rs.getString(1);
                    final int entriesEvicted = rs.getInt(2);
                    LOGGER.debug("Deleted {} expired entries for cache '{}'", entriesEvicted, cacheName);

                    final DatabaseCache cache = cacheByName.get(cacheName);
                    if (cache != null) {
                        cache.onEntriesEvicted(entriesEvicted);
                    }
                }
            }

            if (maxSizes.isEmpty()) {
                return;
            }

            maxSizeQuery.setArray(1, connection.createArrayOf("TEXT", cacheNames.toArray(String[]::new)));
            maxSizeQuery.setArray(2, connection.createArrayOf("INT", maxSizes.toArray(Integer[]::new)));
            try (final ResultSet rs = maxSizeQuery.executeQuery()) {
                while (rs.next()) {
                    final String cacheName = rs.getString(1);
                    final int entriesEvicted = rs.getInt(2);
                    LOGGER.debug("Deleted {} entries exceeding the max size for cache '{}'", entriesEvicted, cacheName);

                    final DatabaseCache cache = cacheByName.get(cacheName);
                    if (cache != null) {
                        cache.onEntriesEvicted(entriesEvicted);
                    }
                }
            }
        }

        LOGGER.debug("Cache maintenance completed");
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            return;
        }

        if (executor != null) {
            executor.close();
        }
    }

}
