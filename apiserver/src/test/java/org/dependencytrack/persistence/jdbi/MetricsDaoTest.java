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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class MetricsDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private MetricsDao metricsDao;
    private MetricsTestDao metricsTestDao;

    @Before
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        metricsDao = jdbiHandle.attach(MetricsDao.class);
        metricsTestDao = jdbiHandle.attach(MetricsTestDao.class);
    }

    @After
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testGetProjectMetricsForXDays() {
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);

        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 40);

        var metrics = new ProjectMetrics();
        metrics.setProjectId(project.getId());
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        metricsTestDao.createProjectMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 30);
        metrics = new ProjectMetrics();
        metrics.setProjectId(project.getId());
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        metricsTestDao.createProjectMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 20);
        metrics = new ProjectMetrics();
        metrics.setProjectId(project.getId());
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        metricsTestDao.createProjectMetrics(metrics);

        var projectMetrics = withJdbiHandle(handle ->
                handle.attach(MetricsDao.class).getProjectMetricsSince(project.getId(), Instant.now().minus(Duration.ofDays(35))));
        assertThat(projectMetrics.size()).isEqualTo(2);
        assertThat(projectMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(projectMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    @Test
    public void testGetDependencyMetricsForXDays() {
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);
        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 40);
        var metrics = new DependencyMetrics();
        metrics.setProjectId(project.getId());
        metrics.setComponentId(component.getId());
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        metricsTestDao.createDependencyMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 30);
        metrics = new DependencyMetrics();
        metrics.setProjectId(project.getId());
        metrics.setComponentId(component.getId());
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        metricsTestDao.createDependencyMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 20);
        metrics = new DependencyMetrics();
        metrics.setProjectId(project.getId());
        metrics.setComponentId(component.getId());
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        metricsTestDao.createDependencyMetrics(metrics);

        var dependencyMetrics = metricsDao.getDependencyMetricsSince(component.getId(), Instant.now().minus(Duration.ofDays(35)));
        assertThat(dependencyMetrics.size()).isEqualTo(2);
        assertThat(dependencyMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(dependencyMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    @Test
    public void testCreateMetricsPartitionsForToday() {
        metricsDao.createMetricsPartitionsForDate(LocalDate.now().toString(), LocalDate.now().plusDays(1).toString());
        var today = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);

        var metricsPartition = metricsDao.getProjectMetricsPartitions();
        assertThat(metricsPartition.contains("\"PROJECTMETRICS_%s\"".formatted(today))).isTrue();

        metricsPartition = metricsDao.getDependencyMetricsPartitions();
        assertThat(metricsPartition.contains("\"DEPENDENCYMETRICS_%s\"".formatted(today))).isTrue();

        // If called again on the same day with partitions already created,
        // It won't create more.
        metricsDao.createMetricsPartitionsForDate(LocalDate.now().toString(), LocalDate.now().plusDays(1).toString());
        assertThat(Collections.frequency(metricsDao.getProjectMetricsPartitions(), "\"PROJECTMETRICS_%s\"".formatted(today))).isEqualTo(1);
        assertThat(Collections.frequency(metricsDao.getDependencyMetricsPartitions(), "\"DEPENDENCYMETRICS_%s\"".formatted(today))).isEqualTo(1);
    }
}