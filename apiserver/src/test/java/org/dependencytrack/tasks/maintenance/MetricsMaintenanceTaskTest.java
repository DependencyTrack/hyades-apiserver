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
import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.function.BiConsumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_METRICS_RETENTION_DAYS;

public class MetricsMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    public void test() {
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

        createComponentMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createComponentMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createComponentMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        createProjectMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createProjectMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createProjectMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        createPortfolioMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createPortfolioMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createPortfolioMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        final var task = new MetricsMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.inform(new MetricsMaintenanceEvent()));

        assertThat(qm.getDependencyMetrics(component).getList(DependencyMetrics.class)).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));

        assertThat(qm.getProjectMetrics(project).getList(ProjectMetrics.class)).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));

        assertThat(qm.getPortfolioMetrics().getList(PortfolioMetrics.class)).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));
    }

    @Test
    public void testWithInactiveProject() {
        qm.createConfigProperty(
                MAINTENANCE_METRICS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setInactiveSince(new Date());
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

        createComponentMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createComponentMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createComponentMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        createProjectMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createProjectMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createProjectMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        createPortfolioMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createPortfolioMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createPortfolioMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        final var task = new MetricsMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.inform(new MetricsMaintenanceEvent()));

        assertThat(qm.getDependencyMetrics(component).getList(DependencyMetrics.class)).satisfiesExactlyInAnyOrder(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89),
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(90), // Retained b/c project is inactive.
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(91)); // Retained b/c project is inactive.

        assertThat(qm.getProjectMetrics(project).getList(ProjectMetrics.class)).satisfiesExactlyInAnyOrder(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89),
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(90), // Retained b/c project is inactive.
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(91)); // Retained b/c project is inactive.

        assertThat(qm.getPortfolioMetrics().getList(PortfolioMetrics.class)).satisfiesExactlyInAnyOrder(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));
    }

}