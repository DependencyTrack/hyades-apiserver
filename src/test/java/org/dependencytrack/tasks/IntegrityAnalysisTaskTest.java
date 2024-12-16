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
import org.dependencytrack.event.IntegrityAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;

public class IntegrityAnalysisTaskTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Before
    public void before() throws Exception {
        super.before();

        environmentVariables.set("INTEGRITY_CHECK_ENABLED", "true");
    }

    @Test
    public void shouldPerformIntegrityAnalysisIfMetaDataExists() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        IntegrityMetaComponent integrityData = qm.persist(integrityMetaComponent);

        new IntegrityAnalysisTask().inform(new IntegrityAnalysisEvent(c.getUuid(), qm.detach(IntegrityMetaComponent.class, integrityData.getId())));
        IntegrityAnalysis integrityResult = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(integrityResult).isNotNull();
        assertThat(integrityResult.getIntegrityCheckStatus()).isEqualTo(HASH_MATCH_PASSED);
    }

    @Test
    public void shouldNotPerformAnalysisIfComponentUuidIsMissing() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        IntegrityMetaComponent integrityData = qm.persist(integrityMetaComponent);

        new IntegrityAnalysisTask().inform(new IntegrityAnalysisEvent(null, qm.detach(IntegrityMetaComponent.class, integrityData.getId())));
        IntegrityAnalysis integrityResult = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(integrityResult).isNull();
    }
}
