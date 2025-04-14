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

import alpine.model.ManagedUser;
import alpine.resources.AlpineRequest;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class MetricsDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private MetricsDao metricsDao;

    @Before
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        metricsDao = jdbiHandle.attach(MetricsDao.class);
    }

    @After
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testGetPortfolioMetricsForXDays() {
        var metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        qm.persist(metrics);

        metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        List<PortfolioMetrics> portfolioMetrics = metricsDao.getPortfolioMetricsXDays(Duration.ofDays(35));
        assertThat(portfolioMetrics.size()).isEqualTo(2);
        assertThat(portfolioMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(portfolioMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    @Test
    public void testGetProjectMetricsForXDays() {
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);
        final ManagedUser managedUser = qm.createManagedUser("username", "passwordHash");
        final var request = new AlpineRequest(
                /* principal */ managedUser,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null
        );

        var metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        qm.persist(metrics);

        metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        var projectMetrics = withJdbiHandle(request, handle ->
                handle.attach(MetricsDao.class).getProjectMetricsXDays(project.getId(), Duration.ofDays(35)));
        assertThat(projectMetrics.size()).isEqualTo(2);
        assertThat(projectMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(projectMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }
}