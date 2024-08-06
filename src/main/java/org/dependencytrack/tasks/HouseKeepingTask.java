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
import org.dependencytrack.persistence.jdbi.VulnerabilityScanDao;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.storage.BomUploadStorage;
import org.dependencytrack.util.LockProvider;

import java.io.IOException;
import java.time.Duration;

import static org.dependencytrack.common.ConfigKey.BOM_UPLOAD_STORAGE_RETENTION_DURATION;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
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

        try {
            LockProvider.executeWithLock(HOUSEKEEPING_TASK_LOCK, (Runnable) this::informLocked);
        } catch (Throwable t) {
            LOGGER.error("Failed to complete housekeeping activities", t);
        }
    }

    private void informLocked() {
        try {
            enforceBomUploadRetention();
        } catch (IOException | RuntimeException e) {
            LOGGER.error("Failed to enforce BOM upload retention", e);
        }

        try {
            enforceVulnerabilityScanRetention();
        } catch (RuntimeException e) {
            LOGGER.error("Failed to enforce vulnerability scan retention", e);
        }

        // TODO: Enforce retention for metrics?
        // TODO: Remove RepositoryMetaComponent records for which no matching Component exists anymore?
        // TODO: Remove IntegrityMetaComponent records for which no matching Component exists anymore?
        // TODO: Move WorkflowStateCleanupTask here.
    }

    private void enforceBomUploadRetention() throws IOException {
        final Duration retentionDuration = Duration.parse(config.getProperty(BOM_UPLOAD_STORAGE_RETENTION_DURATION));
        LOGGER.info("Deleting uploaded BOMs older than %s from storage".formatted(retentionDuration));

        try (final var storage = pluginManager.getExtension(BomUploadStorage.class)) {
            final int bomsDeleted = storage.deleteBomsForRetentionDuration(retentionDuration);
            LOGGER.info("Deleted %s BOMs for retention duration %s"
                    .formatted(bomsDeleted == 0 ? "no" : bomsDeleted, retentionDuration));
        }
    }

    private void enforceVulnerabilityScanRetention() {
        final Duration retentionDuration = Duration.ofDays(1); // TODO: Make configurable?
        LOGGER.info("Deleting vulnerability scans older than %s".formatted(retentionDuration));

        final int scansDeleted = inJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityScanDao.class);
            return dao.deleteAllForRetentionDuration(retentionDuration);
        });
        LOGGER.info("Deleted %s vulnerability scans for retention duration %s"
                .formatted(scansDeleted == 0 ? "no" : scansDeleted, retentionDuration));
    }

}
