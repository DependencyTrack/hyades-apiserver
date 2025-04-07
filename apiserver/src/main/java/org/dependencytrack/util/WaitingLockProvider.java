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
package org.dependencytrack.util;

import alpine.common.logging.Logger;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;
import jakarta.validation.constraints.NotNull;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * @since 5.5.0
 */
class WaitingLockProvider implements LockProvider {

    private static final Logger LOGGER = Logger.getLogger(WaitingLockProvider.class);

    private final LockProvider delegateLockProvider;
    private final Duration pollInterval;
    private final Duration waitTimeout;

    WaitingLockProvider(final LockProvider delegateLockProvider, final Duration pollInterval, final Duration waitTimeout) {
        this.delegateLockProvider = delegateLockProvider;
        this.pollInterval = pollInterval;
        this.waitTimeout = waitTimeout;
    }

    @NotNull
    @Override
    public Optional<SimpleLock> lock(@NotNull final LockConfiguration lockConfiguration) {
        final Instant waitStart = Instant.now();

        Optional<SimpleLock> lock;
        while (Instant.now().isBefore(waitStart.plus(waitTimeout))) {
            lock = delegateLockProvider.lock(lockConfiguration);

            if (lock.isPresent()) {
                LOGGER.debug("Lock acquired: %s".formatted(lockConfiguration.getName()));
                return lock;
            }

            try {
                LOGGER.debug("Failed to acquire lock %s; Retrying in %s".formatted(lockConfiguration.getName(), pollInterval));

                //noinspection BusyWait
                Thread.sleep(pollInterval.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Thread was interrupted while waiting for lock %s".formatted(lockConfiguration.getName()), e);
            }
        }

        LOGGER.warn("Failed to obtain lock %s after waiting for %s".formatted(lockConfiguration.getName(), waitTimeout));
        return Optional.empty();
    }

}
