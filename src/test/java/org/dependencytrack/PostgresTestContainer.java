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

import com.github.dockerjava.api.command.InspectContainerResponse;
import org.dependencytrack.persistence.migration.MigrationInitializer;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.TestcontainersConfiguration;

public class PostgresTestContainer extends PostgreSQLContainer<PostgresTestContainer> {

    @SuppressWarnings("resource")
    public PostgresTestContainer() {
        super(DockerImageName.parse("postgres:11-alpine"));
        withUsername("dtrack");
        withPassword("dtrack");
        withDatabaseName("dtrack");
        withLabel("owner", "hyades-apiserver");

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
            MigrationInitializer.runMigration(dataSource);
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute migrations", e);
        }
    }

    public void stopWhenNotReusing() {
        if (!TestcontainersConfiguration.getInstance().environmentSupportsReuse() || !isShouldBeReused()) {
            stop();
        }
    }

}
