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
package org.dependencytrack.persistence.jdbi;

import alpine.server.persistence.PersistenceManagerFactory;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.jdbi.v3.core.Jdbi;
import org.junit.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class JdbiFactoryTest extends PersistenceCapableTest {

    @Test
    public void testGlobalInstance() {
        final Jdbi jdbi = JdbiFactory.createJdbi();

        // Issue a test query to ensure the JDBI instance is functional.
        final Integer queryResult = jdbi.withHandle(handle ->
                handle.createQuery("SELECT 666").mapTo(Integer.class).one());
        assertThat(queryResult).isEqualTo(666);

        // Ensure that the same JDBI instance is returned.
        // Because the underlying PMF did not change, the global JDBI instance must remain untouched.
        assertThat(JdbiFactory.createJdbi()).isEqualTo(jdbi);
    }

    @Test
    public void testGlobalInstanceWithJdoTransaction() {
        qm.runInTransaction(() -> {
            // Create a new project.
            final var project = new Project();
            project.setName("acme-app");
            project.setVersion("1.0.0");
            qm.getPersistenceManager().makePersistent(project);

            // Query for the created project, despite its creation not having been committed yet.
            // Because the global JDBI instance uses a different connection than the QueryManager,
            // it won't be able to see the yet-uncommitted change.
            final Optional<String> projectName = JdbiFactory.createJdbi().withHandle(handle ->
                    handle.createQuery("SELECT \"NAME\" FROM \"PROJECT\"").mapTo(String.class).findFirst());
            assertThat(projectName).isNotPresent();
        });
    }

    @Test
    public void testGlobalInstanceWhenPmfChanges() {
        final Jdbi jdbi = JdbiFactory.createJdbi();

        // Close the PMF and ensure that the JDBI instance is no longer usable.
        PersistenceManagerFactory.tearDown();
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> jdbi.withHandle(handle ->
                        handle.createQuery("SELECT 666").mapTo(Integer.class).one()))
                .withMessage("Pool not open");

        // Create a new QueryManager.
        configurePmf(postgresContainer);

        // Request the global JDBI instance again and verify it differs from the original one.
        // Because the PMF changed, a new instance must have been created.
        final Jdbi otherJdbi = JdbiFactory.createJdbi();
        assertThat(otherJdbi).isNotEqualTo(jdbi);

        // Issue a test query to ensure the new JDBI instance is functional.
        final Integer queryResult = otherJdbi.withHandle(handle ->
                handle.createQuery("SELECT 666").mapTo(Integer.class).one());
        assertThat(queryResult).isEqualTo(666);
    }

    @Test
    public void testLocalInstanceOutsideOfJdoTransaction() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> JdbiFactory.createLocalJdbi(qm))
                .withMessageContaining("Local JDBI instances must not be used outside of an active JDO transaction");
    }

    @Test
    public void testLocalInstanceWithJdoTransaction() {
        qm.runInTransaction(() -> {
            // Create a new project.
            final var project = new Project();
            project.setName("acme-app");
            project.setVersion("1.0.0");
            qm.getPersistenceManager().makePersistent(project);

            // Query for the created project, despite its creation not having been committed yet.
            // Because the local JDBI instance uses the same connection as the QueryManager,
            // it must be able to see the yet-uncommitted change.
            final Optional<String> projectName = JdbiFactory.createLocalJdbi(qm).withHandle(handle ->
                    handle.createQuery("SELECT \"NAME\" FROM \"PROJECT\"").mapTo(String.class).findFirst());
            assertThat(projectName).contains("acme-app");

            // Ensure the connection is still usable after being returned from JDBI,
            // by creating another record using the QueryManager.
            final var component = new Component();
            component.setProject(project);
            component.setName("acme-lib");
            component.setVersion("2.0.0");
            qm.getPersistenceManager().makePersistent(component);
        });
    }

}