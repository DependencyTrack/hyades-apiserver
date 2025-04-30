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
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;

import java.sql.PreparedStatement;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Date;

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
    public void testGetPortfolioMetricsForXDays() throws Exception {
        createPartitionForXDaysBefore("PORTFOLIOMETRICS", 40);
        var metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        qm.persist(metrics);

        createPartitionForXDaysBefore("PORTFOLIOMETRICS", 30);
        metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        createPartitionForXDaysBefore("PORTFOLIOMETRICS", 20);
        metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        var portfolioMetrics = metricsDao.getPortfolioMetricsSince(Instant.now().minus(Duration.ofDays(35)));
        assertThat(portfolioMetrics.size()).isEqualTo(2);
        assertThat(portfolioMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(portfolioMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    @Test
    public void testGetProjectMetricsForXDays() throws Exception {
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);

        createPartitionForXDaysBefore("PROJECTMETRICS", 40);
        var metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        qm.persist(metrics);

        createPartitionForXDaysBefore("PROJECTMETRICS", 30);
        metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        createPartitionForXDaysBefore("PROJECTMETRICS", 20);
        metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        var projectMetrics = withJdbiHandle(handle ->
                handle.attach(MetricsDao.class).getProjectMetricsSince(project.getId(), Instant.now().minus(Duration.ofDays(35))));
        assertThat(projectMetrics.size()).isEqualTo(2);
        assertThat(projectMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(projectMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    @Test
    public void testGetDependencyMetricsForXDays() throws Exception {
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);
        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        createPartitionForXDaysBefore("DEPENDENCYMETRICS", 40);
        var metrics = new DependencyMetrics();
        metrics.setProject(project);
        metrics.setComponent(component);
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        qm.persist(metrics);

        createPartitionForXDaysBefore("DEPENDENCYMETRICS", 30);
        metrics = new DependencyMetrics();
        metrics.setProject(project);
        metrics.setComponent(component);
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        createPartitionForXDaysBefore("DEPENDENCYMETRICS", 20);
        metrics = new DependencyMetrics();
        metrics.setProject(project);
        metrics.setComponent(component);
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        var dependencyMetrics = metricsDao.getDependencyMetricsSince(component.getId(), Instant.now().minus(Duration.ofDays(35)));
        assertThat(dependencyMetrics.size()).isEqualTo(2);
        assertThat(dependencyMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(dependencyMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    private void createPartitionForXDaysBefore(final String tableName, final int daysBefore) throws Exception {
        LocalDate targetDate = LocalDate.now().minusDays(daysBefore);
        createPartitionForDate(tableName, targetDate);
    }

    private void createPartitionForDate(final String tableName, final LocalDate targetDate) throws Exception {
        LocalDate nextDay = targetDate.plusDays(1);
        String partitionSuffix = targetDate.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String partitionName = tableName + "_" + partitionSuffix;
        String sql = String.format("""
                CREATE TABLE IF NOT EXISTS "%s" PARTITION OF "%s"
                FOR VALUES FROM ('%s') TO ('%s')
            """, partitionName, tableName, targetDate, nextDay);

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        try (final PreparedStatement ps = dataSource.getConnection().prepareStatement(sql)) {
            ps.execute();
        }
    }
}