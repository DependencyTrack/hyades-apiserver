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
package org.dependencytrack;

import alpine.Config;
import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import alpine.server.auth.PasswordService;
import alpine.server.persistence.PersistenceManagerFactory;
import org.apache.kafka.clients.producer.MockProducer;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.util.concurrent.TimeoutException;

public abstract class PersistenceCapableTest {

    protected static PostgresTestContainer postgresContainer;
    protected MockProducer<byte[], byte[]> kafkaMockProducer;
    protected QueryManager qm;

    protected static final String TEST_PASSWORD_HASH = new String(
        PasswordService.createHash("testuser".toCharArray()));

    @BeforeAll
    public static void init() {
        Config.enableUnitTests();

        postgresContainer = new PostgresTestContainer();
        postgresContainer.start();

        MemoryConfigSource.setProperty("dt.datasource.url", postgresContainer.getJdbcUrl());
        MemoryConfigSource.setProperty("dt.datasource.username", postgresContainer.getUsername());
        MemoryConfigSource.setProperty("dt.datasource.password", postgresContainer.getPassword());

        new PersistenceManagerFactory().contextInitialized(null);
    }

    @BeforeEach
    public void before() throws Exception {
        truncateTables(postgresContainer);

        qm = new QueryManager();

        this.kafkaMockProducer = (MockProducer<byte[], byte[]>) KafkaProducerInitializer.getProducer();
    }

    @AfterEach
    public void after() {
        // Ensure that any events dispatched during the test are drained
        // to prevent them from impacting other tests.
        try {
            EventService.getInstance().drain(Duration.ofSeconds(5));
            SingleThreadedEventService.getInstance().drain(Duration.ofSeconds(5));
        } catch (TimeoutException e) {
            throw new IllegalStateException("Failed to drain event services", e);
        }

        // PersistenceManager will refuse to close when there's an active transaction
        // that was neither committed nor rolled back. Unfortunately some areas of the
        // code base can leave such a broken state behind if they run into unexpected
        // errors. See: https://github.com/DependencyTrack/dependency-track/issues/2677
        if (!qm.getPersistenceManager().isClosed()
            && qm.getPersistenceManager().currentTransaction().isActive()) {
            qm.getPersistenceManager().currentTransaction().rollback();
        }

        qm.close();

        KafkaProducerInitializer.tearDown();
    }

    @AfterAll
    public static void tearDownClass() {
        PersistenceManagerFactory.tearDown();
        DataSourceRegistry.getInstance().closeAll();

        if (postgresContainer != null) {
            postgresContainer.stopWhenNotReusing();
        }
    }

    protected static void truncateTables(final PostgreSQLContainer postgresContainer) throws Exception {
        // Truncate all tables to ensure each test starts from a clean slate.
        // https://stackoverflow.com/a/63227261
        try (final Connection connection = postgresContainer.createConnection("");
             final Statement statement = connection.createStatement()) {
            statement.execute("""
                    DO $$ DECLARE
                        r RECORD;
                    BEGIN
                        FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = CURRENT_SCHEMA()) LOOP
                            EXECUTE 'TRUNCATE TABLE ' || QUOTE_IDENT(r.tablename) || ' CASCADE';
                        END LOOP;
                    END $$;
                    """);

            statement.execute("""
                    DO $$
                    DECLARE
                      partition_name TEXT;
                      today_partition_pattern TEXT := format('^(PROJECT|DEPENDENCY)METRICS_%s', TO_CHAR(CURRENT_DATE, 'YYYYMMDD'));
                      tomorrow_partition_pattern TEXT := format('^(PROJECT|DEPENDENCY)METRICS_%s', TO_CHAR(CURRENT_DATE + 1, 'YYYYMMDD'));
                    BEGIN
                      FOR partition_name IN
                        SELECT tablename
                          FROM pg_tables
                         WHERE tablename ~ '^(PROJECT|DEPENDENCY)METRICS_[0-9]{8}$'
                           AND tablename !~ today_partition_pattern
                           AND tablename !~ tomorrow_partition_pattern
                      LOOP
                        EXECUTE format('DROP TABLE "%s"', partition_name);
                      END LOOP;
                    END $$;
                    """);
        }
    }

}
