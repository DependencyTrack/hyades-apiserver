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
package org.dependencytrack.tasks.maintenance;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.maintenance.MetricsMaintenanceEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;

import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.function.BiConsumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_METRICS_RETENTION_DAYS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class MetricsMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    public void test() throws Exception {
        qm.createConfigProperty(
                MAINTENANCE_METRICS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final BiConsumer<Instant, Integer> createComponentMetricsForLastOccurrence = (lastOccurrence, vulns) -> {
            final var metrics = new DependencyMetrics();
            metrics.setProject(project);
            metrics.setComponent(component);
            metrics.setVulnerabilities(vulns);
            metrics.setFirstOccurrence(Date.from(lastOccurrence));
            metrics.setLastOccurrence(Date.from(lastOccurrence));
            qm.persist(metrics);
        };

        final BiConsumer<Instant, Integer> createProjectMetricsForLastOccurrence = (lastOccurrence, vulns) -> {
            final var metrics = new ProjectMetrics();
            metrics.setProject(project);
            metrics.setVulnerabilities(vulns);
            metrics.setFirstOccurrence(Date.from(lastOccurrence));
            metrics.setLastOccurrence(Date.from(lastOccurrence));
            qm.persist(metrics);
        };

        final BiConsumer<Instant, Integer> createPortfolioMetricsForLastOccurrence = (lastOccurrence, vulns) -> {
            final var metrics = new PortfolioMetrics();
            metrics.setVulnerabilities(vulns);
            metrics.setFirstOccurrence(Date.from(lastOccurrence));
            metrics.setLastOccurrence(Date.from(lastOccurrence));
            qm.persist(metrics);
        };

        final Instant now = Instant.now();

        // Create component metrics partitions for dates required
        createPartitionForDaysAgo("DEPENDENCYMETRICS", 91);
        createPartitionForDaysAgo("DEPENDENCYMETRICS", 90);
        createPartitionForDaysAgo("DEPENDENCYMETRICS", 89);

        createComponentMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createComponentMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createComponentMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        // Create project metrics partitions for dates required
        createPartitionForDaysAgo("PROJECTMETRICS", 91);
        createPartitionForDaysAgo("PROJECTMETRICS", 90);
        createPartitionForDaysAgo("PROJECTMETRICS", 89);

        createProjectMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createProjectMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createProjectMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        // Create portfolio metrics partitions for dates required
        createPartitionForDaysAgo("PORTFOLIOMETRICS", 91);
        createPartitionForDaysAgo("PORTFOLIOMETRICS", 90);
        createPartitionForDaysAgo("PORTFOLIOMETRICS", 89);

        createPortfolioMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createPortfolioMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createPortfolioMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        var p1 = withJdbiHandle(handle -> handle.attach(MetricsDao.class).getPortfolioMetricsPartitions());

        final var task = new MetricsMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.inform(new MetricsMaintenanceEvent()));

        var p2 = withJdbiHandle(handle -> handle.attach(MetricsDao.class).getPortfolioMetricsPartitions());

        assertThat(qm.getDependencyMetrics(component).getList(DependencyMetrics.class)).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));

        assertThat(qm.getProjectMetrics(project).getList(ProjectMetrics.class)).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));

        assertThat(qm.getPortfolioMetrics().getList(PortfolioMetrics.class)).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));
    }

    public void createPartitionForDaysAgo(String tableName, int daysAgo) {
        LocalDate targetDate = LocalDate.now().minusDays(daysAgo);
        LocalDate nextDay = targetDate.plusDays(1);
        String partitionSuffix = targetDate.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String partitionName = tableName + "_" + partitionSuffix;
        String sql = String.format("""
            CREATE TABLE IF NOT EXISTS %s PARTITION OF %s
            FOR VALUES FROM ('%s') TO ('%s');
        """,
                "\"" + partitionName + "\"",
                "\"" + tableName + "\"",
                targetDate,
                nextDay
        );
        withJdbiHandle(handle -> handle.execute(sql));
    }
}