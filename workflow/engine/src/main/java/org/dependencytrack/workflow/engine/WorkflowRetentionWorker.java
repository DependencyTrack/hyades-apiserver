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
package org.dependencytrack.workflow.engine;

import org.dependencytrack.workflow.engine.persistence.WorkflowDao;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Update;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class WorkflowRetentionWorker implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowRetentionWorker.class);
    private static final String LOCK_NAME = "workflow-retention";

    private final Jdbi jdbi;
    private final int retentionDays;

    WorkflowRetentionWorker(final Jdbi jdbi, final int retentionDays) {
        this.jdbi = jdbi;
        this.retentionDays = retentionDays;
    }

    @Override
    public void run() {
        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final boolean lockAcquired = dao.tryAcquireAdvisoryLock(LOCK_NAME);
            if (!lockAcquired) {
                LOGGER.debug("Lock {} already held by another instance", LOCK_NAME);
                return;
            }

            // TODO: Limit how many records can be deleted at once?
            final Update update = handle.createUpdate("""
                    delete from workflow_run
                     where completed_at < (NOW() - (:retentionDays * cast('1 day' as interval)))
                    """);

            final int runsDeleted = update
                    .bind("retentionDays", retentionDays)
                    .execute();
            LOGGER.info("Deleted {} runs", runsDeleted);
        });
    }

}
