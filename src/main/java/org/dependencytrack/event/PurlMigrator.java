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
package org.dependencytrack.event;

import alpine.Config;
import alpine.common.logging.Logger;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.LockProvider;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import static org.dependencytrack.tasks.LockName.INTEGRITY_META_INITIALIZER_LOCK;

public class PurlMigrator implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(PurlMigrator.class);
    private final boolean integrityInitializerEnabled;

    public PurlMigrator() {
        this(Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_INITIALIZER_ENABLED));
    }

    PurlMigrator(final boolean integrityInitializerEnabled) {
        this.integrityInitializerEnabled = integrityInitializerEnabled;
    }


    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (integrityInitializerEnabled) {
            try {
                LockProvider.executeWithLock(INTEGRITY_META_INITIALIZER_LOCK, (LockingTaskExecutor.Task) () -> process());
            } catch (Throwable e) {
                throw new RuntimeException("An unexpected error occurred while running Initializer for integrity meta", e);
            }
        } else {
            LOGGER.info("Component integrity initializer is disabled.");
        }
    }

    private void process() {
        LOGGER.info("Initializing integrity meta component sync");
        try (final var qm = new QueryManager()) {
            qm.synchronizeIntegrityMetaComponent();
        }
    }
}
