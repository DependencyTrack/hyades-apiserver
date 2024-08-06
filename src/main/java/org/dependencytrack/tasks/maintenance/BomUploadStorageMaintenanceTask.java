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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.maintenance.BomUploadStorageMaintenanceEvent;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.storage.BomUploadStorage;

import java.io.IOException;
import java.time.Duration;

import static net.javacrumbs.shedlock.core.LockAssert.assertLocked;
import static org.dependencytrack.common.ConfigKey.BOM_UPLOAD_STORAGE_RETENTION_DURATION;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * @since 5.6.0
 */
public class BomUploadStorageMaintenanceTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(BomUploadStorageMaintenanceTask.class);

    private final Config config;
    private final PluginManager pluginManager;

    @SuppressWarnings("unused") // Called by Alpine's event system
    public BomUploadStorageMaintenanceTask() {
        this(Config.getInstance(), PluginManager.getInstance());
    }

    BomUploadStorageMaintenanceTask(final Config config, final PluginManager pluginManager) {
        this.config = config;
        this.pluginManager = pluginManager;
    }

    @Override
    public void inform(final Event event) {
        if (!(event instanceof BomUploadStorageMaintenanceEvent)) {
            return;
        }

        final long startTimeNs = System.nanoTime();
        try {
            LOGGER.info("Starting BOM upload storage maintenance");
            final Statistics statistics = executeWithLock(
                    getLockConfigForTask(BomUploadStorageMaintenanceTask.class),
                    this::informLocked);
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
            Duration retentionDuration,
            int deletedBoms) {
    }

    private Statistics informLocked() throws IOException {
        assertLocked();

        final Duration retentionDuration = Duration.parse(config.getProperty(BOM_UPLOAD_STORAGE_RETENTION_DURATION));

        final int numDeleted;
        try (final var storage = pluginManager.getExtension(BomUploadStorage.class)) {
            numDeleted = storage.deleteBomsForRetentionDuration(retentionDuration);
        }

        return new Statistics(retentionDuration, numDeleted);
    }

}
