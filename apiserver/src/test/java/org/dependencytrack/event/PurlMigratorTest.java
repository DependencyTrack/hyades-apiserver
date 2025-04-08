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
package org.dependencytrack.event;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.junit.Before;
import org.junit.Test;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.FetchStatus.IN_PROGRESS;
import static org.dependencytrack.model.FetchStatus.PROCESSED;

public class PurlMigratorTest extends PersistenceCapableTest {

    final Component componentPersisted = new Component();

    @Before
    public void persistComponentData() {
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        componentPersisted.setProject(projectA);
        componentPersisted.setName("acme-lib-a");
        componentPersisted.setInternal(false);
        componentPersisted.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        componentPersisted.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        qm.persist(componentPersisted);
        kafkaMockProducer.clear();
    }

    @Test
    public void testIntegrityMetaInitializerWhenDisabledByDefault() {
        PurlMigrator initializer = new PurlMigrator(false);
        initializer.contextInitialized(null);
        assertThat(qm.getIntegrityMetaComponentCount()).isZero();
        assertThat(kafkaMockProducer.history().size()).isZero();
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataProcessed() {
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        integrityMetaExisting.setStatus(PROCESSED);
        qm.persist(integrityMetaExisting);
        // data exists in IntegrityMetaComponent so sync will be skipped
        PurlMigrator initializer = new PurlMigrator(true);
        initializer.contextInitialized(null);
        // kafka event is not dispatched
        assertThat(kafkaMockProducer.history().size()).isZero();
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }


    @Test
    public void testIntegrityMetaInitializerWithExistingDataFetchedRecently() {
        // data exists in IntegrityMetaComponent but last fetched 30 min ago < 1 hour wait time
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        integrityMetaExisting.setStatus(IN_PROGRESS);
        integrityMetaExisting.setLastFetch(Date.from(Instant.now().minus(30, ChronoUnit.MINUTES)));
        qm.persist(integrityMetaExisting);

        PurlMigrator initializer = new PurlMigrator(true);
        initializer.contextInitialized(null);
        // kafka event is dispatched
        assertThat(kafkaMockProducer.history().size()).isZero();
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }
}
