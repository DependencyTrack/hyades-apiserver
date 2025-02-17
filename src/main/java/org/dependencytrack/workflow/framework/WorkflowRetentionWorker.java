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
package org.dependencytrack.workflow.framework;

import org.dependencytrack.workflow.framework.persistence.WorkflowDao;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;

final class WorkflowRetentionWorker implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowRetentionWorker.class);
    private static final String LOCK_NAME = "workflow-retention";

    private final Jdbi jdbi;
    private final int deletionBatchSize;
    private final Duration retentionDuration;

    WorkflowRetentionWorker(final Jdbi jdbi, final int deletionBatchSize, final Duration retentionDuration) {
        this.jdbi = jdbi;
        this.deletionBatchSize = deletionBatchSize;
        this.retentionDuration = retentionDuration;
    }

    @Override
    public void run() {
        final Instant cutoff = Instant.now().minus(retentionDuration);
        LOGGER.info("Deleting runs that completed before {}", cutoff);

        int numRunsDeletedTotal = 0;
        int numRunsDeletedLast = -1;

        while ((numRunsDeletedLast == -1 || numRunsDeletedLast > 0)
               && !Thread.currentThread().isInterrupted()) {
            numRunsDeletedLast = jdbi.inTransaction(handle -> {
                final var dao = new WorkflowDao(handle);

                final boolean lockAcquired = dao.tryAcquireAdvisoryLock(LOCK_NAME);
                if (!lockAcquired) {
                    LOGGER.debug("Lock {} already held by another instance", LOCK_NAME);
                    return 0;
                }

                return dao.deleteExpiredRuns(cutoff, deletionBatchSize);
            });

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Deleted batch of {} workflow runs for cutoff {}", numRunsDeletedLast, cutoff);
            }

            numRunsDeletedTotal += numRunsDeletedLast;
        }

        LOGGER.info("Deleted {} workflow runs for cutoff {}", numRunsDeletedTotal, cutoff);
    }

}
