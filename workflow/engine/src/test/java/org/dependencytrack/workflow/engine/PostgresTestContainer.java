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
package org.dependencytrack.workflow.engine;

import com.github.dockerjava.api.command.InspectContainerResponse;
import org.dependencytrack.workflow.engine.migration.MigrationExecutor;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.TestcontainersConfiguration;

import java.lang.management.ManagementFactory;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public final class PostgresTestContainer extends PostgreSQLContainer<PostgresTestContainer> {

    @SuppressWarnings("resource")
    public PostgresTestContainer() {
        super(DockerImageName.parse("postgres:13-alpine"));
        withUsername("workflow");
        withPassword("workflow");
        withDatabaseName("workflow");
        withLabel("owner", "workflow-engine-" + /* JVM name */ ManagementFactory.getRuntimeMXBean().getName());
        withUrlParam("reWriteBatchedInserts", "true");

        // Uncomment this to see queries executed by Postgres:
        //   withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(PostgresTestContainer.class)));
        //   withCommand("-c log_statement=all");

        // NB: Container reuse won't be active unless either:
        //  - The environment variable TESTCONTAINERS_REUSE_ENABLE=true is set
        //  - testcontainers.reuse.enable=true is set in ~/.testcontainers.properties
        withReuse(true);
    }

    @Override
    protected void containerIsStarted(final InspectContainerResponse containerInfo, final boolean reused) {
        super.containerIsStarted(containerInfo, reused);

        if (reused) {
            logger().debug("Reusing container; Migration not necessary");
            return;
        }

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(getJdbcUrl());
        dataSource.setUser(getUsername());
        dataSource.setPassword(getPassword());

        try {
            new MigrationExecutor(dataSource).executeMigration();
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute migrations", e);
        }
    }

    @Override
    public void stop() {
        if (!TestcontainersConfiguration.getInstance().environmentSupportsReuse() || !isShouldBeReused()) {
            super.stop();
        }
    }

    public void truncateTables() {
        try (final Connection connection = createConnection("");
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
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to truncate tables", e);
        }
    }
}
