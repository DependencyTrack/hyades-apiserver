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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;

import java.util.List;

public interface WorkflowDao {

    @SqlBatch("""
            UPDATE "WORKFLOW_STATE"
               SET "STATUS" = :status
                 , "FAILURE_REASON" = :failureReason
                 , "UPDATED_AT" = NOW()
             WHERE "TOKEN" = :token
               AND "STEP" = :step
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    @RegisterBeanMapper(WorkflowState.class)
    List<WorkflowState> updateAllStates(@Bind WorkflowStep step,
                                        @Bind("token") List<String> tokens,
                                        @Bind("status") List<WorkflowStatus> statuses,
                                        @Bind("failureReason") List<String> failureReasons);

    @SqlBatch("""
            UPDATE "WORKFLOW_STATE"
               SET "STATUS" = :status
                 , "FAILURE_REASON" = :failureReason
                 , "UPDATED_AT" = NOW()
             WHERE "TOKEN" = :token
               AND "STEP" = :step
               AND "STATUS" = 'PENDING'
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    @RegisterBeanMapper(WorkflowState.class)
    List<WorkflowState> updateAllStatesIfPending(@Bind WorkflowStep step,
                                                 @Bind("token") List<String> tokens,
                                                 @Bind("status") List<WorkflowStatus> statuses,
                                                 @Bind("failureReason") List<String> failureReasons);

    @SqlBatch("""
            WITH RECURSIVE
            "CTE_PARENT" ("ID") AS (
              SELECT "ID"
                FROM "WORKFLOW_STATE"
               WHERE "STEP" = :step
                 AND "TOKEN" = :token
            ),
            "CTE_CHILDREN" ("ID") AS (
              SELECT "ID"
                FROM "WORKFLOW_STATE"
               WHERE "PARENT_STEP_ID" = (SELECT "ID" FROM "CTE_PARENT")
               UNION ALL
              SELECT "CHILD"."ID"
                FROM "WORKFLOW_STATE" AS "CHILD"
               INNER JOIN "CTE_CHILDREN" AS "PARENT"
                  ON "PARENT"."ID" = "CHILD"."PARENT_STEP_ID"
            )
            UPDATE "WORKFLOW_STATE"
               SET "STATUS" = 'CANCELLED'
                 , "UPDATED_AT" = NOW()
             WHERE "ID" IN (SELECT "ID" FROM "CTE_CHILDREN")
            """)
    void cancelAllChildren(@Bind WorkflowStep step, @Bind("token") List<String> tokens);

}
