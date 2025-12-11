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
package org.dependencytrack.dex.engine;

import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.dex.engine.support.LockSupport.tryAcquireAdvisoryLock;

final class RetentionWorker implements Closeable {

    private static final long ADVISORY_LOCK_ID = 3218488535236088498L;
    private static final Logger LOGGER = LoggerFactory.getLogger(RetentionWorker.class);

    private final Jdbi jdbi;
    private final Duration retentionDuration;
    private final Duration initialDelay;
    private final Duration interval;
    private @Nullable ScheduledExecutorService executor;

    RetentionWorker(
            final Jdbi jdbi,
            final Duration retentionDuration,
            final Duration initialDelay,
            final Duration interval) {
        this.jdbi = jdbi;
        this.retentionDuration = retentionDuration;
        this.initialDelay = initialDelay;
        this.interval = interval;
    }

    void start() {
        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name(RetentionWorker.class.getSimpleName())
                        .factory());
        executor.scheduleAtFixedRate(
                () -> {
                    try {
                        enforceRetention();
                    } catch (RuntimeException e) {
                        LOGGER.error("Failed to enforce retention", e);
                    }
                },
                initialDelay.toMillis(),
                interval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.close();
        }
    }

    private void enforceRetention() {
        jdbi.useTransaction(handle -> {
            final boolean lockAcquired = tryAcquireAdvisoryLock(handle, ADVISORY_LOCK_ID);
            if (!lockAcquired) {
                LOGGER.debug("Lock is held by another instance");
                return;
            }

            final Update update = handle.createUpdate("""
                    with cte_candidates as (
                      select id
                        from dex_workflow_run
                       where completed_at < (NOW() - (:retentionDuration))
                       order by completed_at
                       limit 100 -- TODO: Make configurable.
                         for no key update
                    )
                    delete from dex_workflow_run
                     where id in (select id from cte_candidates)
                    """);

            final int runsDeleted = update
                    .bind("retentionDuration", retentionDuration)
                    .execute();
            LOGGER.info("Deleted {} workflow run(s)", runsDeleted);
        });
    }

}
