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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.HouseKeepingEvent;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.persistence.jdbi.VulnerabilityScanDao;
import org.dependencytrack.persistence.jdbi.WorkflowDao;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.storage.BomUploadStorage;
import org.dependencytrack.util.LockProvider;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.dependencytrack.common.ConfigKey.BOM_UPLOAD_STORAGE_RETENTION_DURATION;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_RETENTION_DURATION;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_STEP_TIMEOUT_DURATION;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.tasks.LockName.HOUSEKEEPING_TASK_LOCK;

/**
 * @since 5.6.0
 */
public class HouseKeepingTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(HouseKeepingTask.class);

    private final Config config;
    private final PluginManager pluginManager;

    @SuppressWarnings("unused") // Called by Alpine's event system
    public HouseKeepingTask() {
        this(Config.getInstance());
    }

    HouseKeepingTask(final Config config) {
        this.config = config;
        this.pluginManager = PluginManager.getInstance();
    }

    @Override
    public void inform(final Event event) {
        if (!(event instanceof HouseKeepingEvent)) {
            return;
        }

        LOGGER.info("Starting housekeeping activities");
        final long startTimeNs = System.nanoTime();

        try {
            LockProvider.executeWithLock(HOUSEKEEPING_TASK_LOCK, (Runnable) this::informLocked);

            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.info("Housekeeping completed in %s".formatted(taskDuration));
        } catch (Throwable t) {
            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.error("Housekeeping failed to complete after %s".formatted(taskDuration), t);
        }
    }

    private void informLocked() {
        try {
            performBomUploadHouseKeeping();
        } catch (IOException | RuntimeException e) {
            LOGGER.error("Failed perform housekeeping of BOM uploads", e);
        }

        try {
            performVulnerabilityScanHouseKeeping();
        } catch (RuntimeException e) {
            LOGGER.error("Failed to perform housekeeping of vulnerability scans", e);
        }

        try {
            performWorkflowHouseKeeping();
        } catch (RuntimeException e) {
            LOGGER.error("Failed to perform housekeeping of workflows", e);
        }

        // TODO: Enforce retention for metrics?
        // TODO: Remove RepositoryMetaComponent records for which no matching Component exists anymore?
        // TODO: Remove IntegrityMetaComponent records for which no matching Component exists anymore?
        // TODO: Remove VulnerableSoftware records that are no longer associated with any vulnerability?
    }

    private void performBomUploadHouseKeeping() throws IOException {
        final Duration retentionDuration = Duration.parse(config.getProperty(BOM_UPLOAD_STORAGE_RETENTION_DURATION));

        try (final var storage = pluginManager.getExtension(BomUploadStorage.class)) {
            final int bomsDeleted = storage.deleteBomsForRetentionDuration(retentionDuration);
            if (bomsDeleted > 0) {
                LOGGER.warn("Deleted %s BOM(s) for retention duration %s"
                        .formatted(bomsDeleted, retentionDuration));
            }
        }
    }

    private void performVulnerabilityScanHouseKeeping() {
        final Duration retentionDuration = Duration.ofDays(1); // TODO: Make configurable?

        final int scansDeleted = inJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityScanDao.class);
            return dao.deleteAllForRetentionDuration(retentionDuration);
        });
        if (scansDeleted > 0) {
            LOGGER.info("Deleted %s vulnerability scan(s) for retention duration %s"
                    .formatted(scansDeleted, retentionDuration));
        }
    }

    private void performWorkflowHouseKeeping() {
        final Duration timeoutDuration = Duration.parse(config.getProperty(WORKFLOW_STEP_TIMEOUT_DURATION));
        final Duration retentionDuration = Duration.parse(config.getProperty(WORKFLOW_RETENTION_DURATION));

        useJdbiHandle(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final int numTimedOut = dao.transitionAllPendingStepsToTimedOutForTimeout(timeoutDuration);
            if (numTimedOut > 0) {
                LOGGER.warn("Transitioned %d workflow step(s) from %s to %s for timeout %s"
                        .formatted(numTimedOut, WorkflowStatus.PENDING, WorkflowStatus.TIMED_OUT, timeoutDuration));
            }

            handle.useTransaction(ignored -> {
                final List<Long> failedStepIds = dao.transitionAllTimedOutStepsToFailedForTimeout(timeoutDuration);
                if (failedStepIds.isEmpty()) {
                    return;
                }

                LOGGER.warn("Transitioned %d workflow step(s) from %s to %s for timeout %s"
                        .formatted(failedStepIds.size(), WorkflowStatus.TIMED_OUT, WorkflowStatus.FAILED, timeoutDuration));

                final int numCancelled = Arrays.stream(dao.cancelAllChildrenByParentStepIdAnyOf(failedStepIds)).sum();
                if (numCancelled > 0) {
                    LOGGER.warn("Transitioned %d workflow step(s) to %s because their parent steps transitioned to %s"
                            .formatted(numCancelled, WorkflowStatus.CANCELLED, WorkflowStatus.FAILED));
                }
            });

            final int numDeleted = dao.deleteAllForRetention(retentionDuration);
            if (numDeleted > 0) {
                LOGGER.info("Deleted %s workflow(s) that have not been updated within %s"
                        .formatted(numDeleted, retentionDuration));
            }
        });
    }

}
