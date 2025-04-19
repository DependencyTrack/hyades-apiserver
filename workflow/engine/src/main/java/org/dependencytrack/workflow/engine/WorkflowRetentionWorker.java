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
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

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

            final List<String> partitionNames = getPartitionNames(handle);
            for (final String partitionName : partitionNames) {
                LOGGER.info("Dropping partition {}", partitionName);
                handle.execute("drop table %s".formatted(partitionName));
            }

            final List<String> createdPartitionNames = createNextPartitions(handle);
            for (final String partitionName : createdPartitionNames) {
                LOGGER.info("Created partition {}", partitionName);
            }
        });
    }

    private List<String> getPartitionNames(final Handle jdbiHandle) {
        final Query archivePartitionsQuery = jdbiHandle.createQuery("""
                select inhrelid::regclass::text as partition_name
                  from pg_inherits
                 where inhparent in ('workflow_run_archive'::regclass, 'workflow_run_journal'::regclass)
                   and substring(inhrelid::regclass::text, '_(\\d{8})$')::date < (current_date - interval '1 day' * :retentionDays)::date
                 order by partition_name
                """);

        return archivePartitionsQuery
                .bind("retentionDays", retentionDays)
                .mapTo(String.class)
                .list();
    }

    private List<String> createNextPartitions(final Handle jdbiHandle) {
        final Query createPartitionsQuery = jdbiHandle.createQuery("""
                select create_workflow_run_archive_partition(current_date)
                 union all
                select create_workflow_run_journal_archive_partition(current_date)
                 union all
                select create_workflow_run_archive_partition((current_date + interval '1 day')::date)
                 union all
                select create_workflow_run_journal_archive_partition((current_date + interval '1 day')::date)
                """);

        return createPartitionsQuery
                .mapTo(String.class)
                .filter(Objects::nonNull)
                .list();
    }

}
