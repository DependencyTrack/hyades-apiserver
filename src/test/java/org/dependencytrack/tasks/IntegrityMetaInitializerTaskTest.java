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
package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.IntegrityMetaInitializerEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.FetchStatus.IN_PROGRESS;

public class IntegrityMetaInitializerTaskTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    final Component componentPersisted = new Component();

    @Before
    public void persistComponentData() {
        environmentVariables.set("INTEGRITY_INITIALIZER_ENABLED", "true");
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
    public void testIntegrityMetaInitializer() {
        final var IntegrityMetaComponent = new IntegrityMetaComponent();
        IntegrityMetaComponent.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        qm.persist(IntegrityMetaComponent);
        new IntegrityMetaInitializerTask().inform(new IntegrityMetaInitializerEvent());
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name())
        );
    }

    @Test
    public void shouldNotDispatchEventIfPackageTypeIsNotSupported() {
        final var IntegrityMetaComponent = new IntegrityMetaComponent();
        IntegrityMetaComponent.setPurl("pkg:golang/github.com/prometheus/client_model@0.2.0?type=module");
        qm.persist(IntegrityMetaComponent);
        new IntegrityMetaInitializerTask().inform(new IntegrityMetaInitializerEvent());
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
        assertThat(kafkaMockProducer.history()).isEmpty();
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataFetchedNotRecently() {
        // data exists in IntegrityMetaComponent but last fetched 3 hours ago > 1 hour wait time
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        integrityMetaExisting.setStatus(IN_PROGRESS);
        integrityMetaExisting.setLastFetch(Date.from(Instant.now().minus(3, ChronoUnit.HOURS)));
        qm.persist(integrityMetaExisting);
        new IntegrityMetaInitializerTask().inform(new IntegrityMetaInitializerEvent());
        // kafka event is dispatched
        assertThat(kafkaMockProducer.history().size()).isEqualTo(1);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }

    @Test
    public void testIntegrityMetaInitializerWithExistingDataNotProcessed() {
        // data exists in IntegrityMetaComponent but not processed yet
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl(componentPersisted.getPurl().toString());
        qm.persist(integrityMetaExisting);
        new IntegrityMetaInitializerTask().inform(new IntegrityMetaInitializerEvent());
        // kafka event is dispatched
        assertThat(kafkaMockProducer.history().size()).isEqualTo(1);
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }

    @Test
    public void testIntegrityMetaInitializerWithNonExistentComponent() {
        // Create a meta component.
        var integrityMetaExisting = new IntegrityMetaComponent();
        integrityMetaExisting.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        qm.persist(integrityMetaExisting);

        // Delete the component such that the meta component's PURL no longer matches
        // any record in the COMPONENT table.
        qm.delete(componentPersisted);

        // No exception must be raised.
        assertThatNoException().isThrownBy(() -> new IntegrityMetaInitializerTask().inform(new IntegrityMetaInitializerEvent()));

        // No Kafka record must be sent.
        assertThat(kafkaMockProducer.history().size()).isZero();
    }

}
