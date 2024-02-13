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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack;

import alpine.Config;
import alpine.server.persistence.PersistenceManagerFactory;
import org.apache.kafka.clients.producer.MockProducer;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.migration.MigrationInitializer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Properties;

public abstract class PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    protected static PostgreSQLContainer<?> postgresContainer;
    protected MockProducer<byte[], byte[]> kafkaMockProducer;
    protected QueryManager qm;

    @BeforeClass
    public static void init() throws Exception {
        Config.enableUnitTests();

        postgresContainer = createPostgresContainer();
        postgresContainer.start();
        runMigrations(postgresContainer);
    }

    @Before
    public void before() throws Exception {
        truncateTables(postgresContainer);
        configurePmf(postgresContainer);

        qm = new QueryManager();

        environmentVariables.set("TASK_PORTFOLIO_REPOMETAANALYSIS_LOCKATLEASTFORINMILLIS", "2000");
        this.kafkaMockProducer = (MockProducer<byte[], byte[]>) KafkaProducerInitializer.getProducer();
    }

    @After
    public void after() {
        // PersistenceManager will refuse to close when there's an active transaction
        // that was neither committed nor rolled back. Unfortunately some areas of the
        // code base can leave such a broken state behind if they run into unexpected
        // errors. See: https://github.com/DependencyTrack/dependency-track/issues/2677
        if (!qm.getPersistenceManager().isClosed()
            && qm.getPersistenceManager().currentTransaction().isActive()) {
            qm.getPersistenceManager().currentTransaction().rollback();
        }

        PersistenceManagerFactory.tearDown();
        KafkaProducerInitializer.tearDown();
    }

    @AfterClass
    public static void tearDownClass() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @SuppressWarnings("resource")
    protected static PostgreSQLContainer<?> createPostgresContainer() {
        return new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"))
                .withUsername("dtrack")
                .withPassword("dtrack")
                .withDatabaseName("dtrack");
    }

    protected static void configurePmf(final PostgreSQLContainer<?> postgresContainer) {
        final var dnProps = new Properties();
        dnProps.put(PropertyNames.PROPERTY_PERSISTENCE_UNIT_NAME, "Alpine");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_DATABASE, "false");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_TABLES, "false");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_COLUMNS, "false");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_CONSTRAINTS, "false");
        dnProps.put("datanucleus.schema.generatedatabase.mode", "none");
        dnProps.put("datanucleus.query.jdoql.allowall", "true");
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_URL, postgresContainer.getJdbcUrl());
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, postgresContainer.getDriverClassName());
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_USER_NAME, postgresContainer.getUsername());
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_PASSWORD, postgresContainer.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);
    }

    protected static void runMigrations(final PostgreSQLContainer<?> postgresContainer) throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        MigrationInitializer.runMigration(dataSource, /* silent */ true);
    }

    protected static void truncateTables(final PostgreSQLContainer<?> postgresContainer) throws Exception {
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
        }
    }

}
