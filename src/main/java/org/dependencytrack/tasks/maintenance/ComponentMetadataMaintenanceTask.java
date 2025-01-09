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
import org.dependencytrack.event.maintenance.ComponentMetadataMaintenanceEvent;
import org.dependencytrack.persistence.jdbi.ComponentMetaDao;
import org.jdbi.v3.core.Handle;

import java.time.Duration;

import static net.javacrumbs.shedlock.core.LockAssert.assertLocked;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * @since 5.6.0
 */
public class ComponentMetadataMaintenanceTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ComponentMetadataMaintenanceTask.class);

    @Override
    public void inform(final Event event) {
        if (!(event instanceof ComponentMetadataMaintenanceEvent)) {
            return;
        }

        final long startTimeNs = System.nanoTime();
        try (final Handle jdbiHandle = openJdbiHandle()) {
            LOGGER.info("Starting component metadata maintenance");
            final Statistics statistics = executeWithLock(
                    getLockConfigForTask(ComponentMetadataMaintenanceTask.class),
                    () -> informLocked(jdbiHandle));
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

    private record Statistics(
            int deletedIntegrityMetadata,
            int deletedRepositoryMetadata) {
    }

    private Statistics informLocked(final Handle jdbiHandle) {
        assertLocked();

        final var dao = jdbiHandle.attach(ComponentMetaDao.class);

        final int numDeletedIntegrityMeta = dao.deleteOrphanIntegrityMetaComponents();
        final int numDeletedRepoMeta = dao.deleteOrphanRepositoryMetaComponents();

        return new Statistics(numDeletedIntegrityMeta, numDeletedRepoMeta);
    }

}
