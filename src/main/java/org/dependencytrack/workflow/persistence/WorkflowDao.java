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
package org.dependencytrack.workflow.persistence;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Query;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public class WorkflowDao {

    private final Handle jdbiHandle;

    public WorkflowDao(Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public List<WorkflowRunHistoryEntryRow> createWorkflowRunHistoryEntries(
            final Collection<NewWorkflowRunHistoryEntry> entries) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "WORKFLOW_RUN_EVENT_HISTORY" (
                  "WORKFLOW_RUN_ID"
                , "TIMESTAMP"
                , "EVENT_TYPE"
                , "ACTIVITY_NAME"
                , "ACTIVITY_INVOCATION_ID"
                , "ARGUMENTS"
                , "RESULT"
                ) VALUES (
                  :workflowRunId
                , :timestamp
                , CAST(:eventType AS WORKFLOW_EVENT_TYPE)
                , :activityName
                , :activityInvocationId
                , CAST(:arguments AS JSONB)
                , CAST(:result AS JSONB)
                )
                """);

        for (final NewWorkflowRunHistoryEntry entry : entries) {
            preparedBatch
                    .bindMethods(entry)
                    .add();
        }

        return preparedBatch
                .executePreparedBatch("*")
                .map(ConstructorMapper.of(WorkflowRunHistoryEntryRow.class))
                .list();
    }

    public List<WorkflowRunHistoryEntryRow> getWorkflowRunHistory(final UUID workflowRunId) {
        final Query query = jdbiHandle.createQuery("""
                SELECT *
                  FROM "WORKFLOW_RUN_EVENT_HISTORY"
                 WHERE "WORKFLOW_RUN_ID" = :workflowRunId
                 ORDER BY "TIMESTAMP"
                """);

        return query
                .bind("workflowRunId", workflowRunId)
                .map(ConstructorMapper.of(WorkflowRunHistoryEntryRow.class))
                .list();
    }

}
