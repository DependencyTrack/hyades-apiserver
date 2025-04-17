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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static net.javacrumbs.shedlock.core.LockAssert.assertLocked;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_DAYS;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_TYPE;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_VERSIONS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

public class ProjectMaintenanceTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ProjectMaintenanceTask.class);

    @Override
    public void inform(final Event event) {
        if (!(event instanceof ProjectMaintenanceEvent)) {
            return;
        }

        final long startTimeNs = System.nanoTime();
        try {
            LOGGER.info("Starting project maintenance");
            final Statistics statistics = executeWithLock(
                    getLockConfigForTask(ProjectMaintenanceTask.class),
                    () -> informLocked());
            if (statistics == null) {
                LOGGER.info("Task is locked by another instance; Skipping");
                return;
            }

            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.info("Completed in %s: %s".formatted(taskDuration, statistics));
        } catch (Throwable e) {
            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.error("Failed to complete after %s".formatted(taskDuration), e);
        }
    }

    private record Statistics(int deletedInactiveProjects) {
    }

    private Statistics informLocked() {
        assertLocked();
        AtomicInteger numDeletedTotal = new AtomicInteger(0);

        final var retentionType = withJdbiHandle(handle ->
                handle.attach(ConfigPropertyDao.class).getOptionalValue(MAINTENANCE_PROJECTS_RETENTION_TYPE, String.class));

        if (!retentionType.isEmpty() && !retentionType.get().isEmpty()) {
            int batchSize = 100;
            if (retentionType.get().equals("AGE")) {

                final int retentionDays = withJdbiHandle(handle ->
                        handle.attach(ConfigPropertyDao.class).getValue(MAINTENANCE_PROJECTS_RETENTION_DAYS, Integer.class));
                final Duration retentionDuration = Duration.ofDays(retentionDays);
                Instant retentionCutOff = Instant.now().minus(retentionDuration);
                Integer numDeletedLastBatch = null;
                while (numDeletedLastBatch == null || numDeletedLastBatch > 0) {
                    final var deletedProjectsBatch = withJdbiHandle(
                            batchHandle -> {
                                final var projectDao = batchHandle.attach(ProjectDao.class);
                                return projectDao.deleteInactiveProjectsForRetentionDuration(retentionCutOff, batchSize);
                            });
                    numDeletedLastBatch = deletedProjectsBatch.size();
                    numDeletedTotal.addAndGet(numDeletedLastBatch);
                    deletedProjectsBatch.forEach(deletedProject ->
                            LOGGER.info("Inactive project deleted: [name:%s, version:%s, inactive since:%s, uuid:%s]".formatted(deletedProject.name(), deletedProject.version(), deletedProject.inactiveSince(), deletedProject.uuid())));
                }
            } else {
                final int versionCountThreshold = withJdbiHandle(handle ->
                        handle.attach(ConfigPropertyDao.class).getValue(MAINTENANCE_PROJECTS_RETENTION_VERSIONS, Integer.class));
                Integer projectLastBatch = null;
                while (projectLastBatch == null || projectLastBatch > 0) {
                    projectLastBatch = inJdbiTransaction(
                            batchHandle -> {
                                final var projectDao = batchHandle.attach(ProjectDao.class);
                                List<String> projectBatch = projectDao.getDistinctProjects(versionCountThreshold, batchSize);
                                for (var projectName : projectBatch) {
                                    final var deletedProjects = projectDao.retainLastXInactiveProjects(projectName, versionCountThreshold);
                                    numDeletedTotal.addAndGet(deletedProjects.size());
                                    deletedProjects.forEach(deletedProject ->
                                            LOGGER.info("Inactive project deleted: [name:%s, version:%s, inactive since:%s, uuid:%s]".formatted(deletedProject.name(), deletedProject.version(), deletedProject.inactiveSince(), deletedProject.uuid())));
                                }
                                return projectBatch.size();
                            });
                }
            }
        } else {
            LOGGER.info("Not deleting inactive projects because it is disabled");
        }
        return new Statistics(numDeletedTotal.get());
    }
}
