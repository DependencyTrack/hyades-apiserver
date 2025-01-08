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
import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_INACTIVE_PROJECTS_RETENTION_DAYS;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE;

public class ProjectMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    public void testWithRetentionTypeAge() {
        qm.createConfigProperty(
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getDefaultPropertyValue(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getDescription());

        qm.createConfigProperty(
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_DAYS.getDescription());

        final var projectA = new Project();
        projectA.setName("acme-app-A");
        projectA.setInactiveSince(Date.from(Instant.now().minus(Duration.ofDays(40))));

        final var projectB = new Project();
        projectB.setName("acme-app-B");
        projectB.setInactiveSince(new Date());
        qm.persist(projectA, projectB);

        // Delete projects older than default 30 days
        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.inform(new ProjectMaintenanceEvent()));

        assertThat(qm.getProjects().getList(Project.class)).satisfiesExactly(
                retainedProject -> assertThat(retainedProject.getName()).isEqualTo("acme-app-B")
        );
    }

//    @Test
//    public void testWithRetentionTypeCadence() {
//        qm.createConfigProperty(
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getGroupName(),
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getPropertyName(),
//                "CADENCE",
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getPropertyType(),
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_TYPE.getDescription());
//
//        qm.createConfigProperty(
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_CADENCE.getGroupName(),
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_CADENCE.getPropertyName(),
//                "1",
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_CADENCE.getPropertyType(),
//                MAINTENANCE_INACTIVE_PROJECTS_RETENTION_CADENCE.getDescription());
//
//        final var project = new Project();
//        project.setName("acme-app-A");
//        project.setVersion("1.0.0");
//        project.setInactiveSince(new Date());
//        qm.persist(project);
//
//        project.setVersion("2.0.0");
//        project.setInactiveSince(new Date());
//        qm.persist(project);
//
//        project.setVersion("3.0.0");
//        qm.persist(project);
//
//        // Retain all active and last 1 inactive projects and delete rest
//        final var task = new ProjectMaintenanceTask();
//        assertThatNoException().isThrownBy(() -> task.inform(new ProjectMaintenanceEvent()));
//
//        assertThat(qm.getProjects().getList(Project.class)).satisfiesExactly(
//                retainedProject -> assertThat(retainedProject.getVersion()).isEqualTo("2.0.0"),
//                retainedProject -> assertThat(retainedProject.getVersion()).isEqualTo("3.0.0")
//        );
//    }
}