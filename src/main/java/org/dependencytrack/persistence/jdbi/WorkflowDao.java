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
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface WorkflowDao extends SqlObject {

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
    List<WorkflowState> updateAllStates(
            @Bind WorkflowStep step,
            @Bind("token") List<UUID> tokens,
            @Bind("status") List<WorkflowStatus> statuses,
            @Bind("failureReason") List<String> failureReasons);

    default Optional<WorkflowState> updateState(
            final WorkflowStep step,
            final UUID token,
            final WorkflowStatus status,
            final String failureReason) {
        final List<WorkflowState> updatedStates = updateAllStates(
                step,
                List.of(token),
                List.of(status),
                Collections.singletonList(failureReason));
        if (updatedStates.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(updatedStates.getFirst());
    }

    @SqlUpdate("""
            UPDATE "WORKFLOW_STATE"
               SET "STARTED_AT" = NOW()
             WHERE "STEP" = :step
               AND "TOKEN" = :token
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    @RegisterBeanMapper(WorkflowState.class)
    WorkflowState startState(@Bind WorkflowStep step, @Bind("token") UUID token);

    @SqlQuery("""
            SELECT "TOKEN"
              FROM "WORKFLOW_STATE"
             WHERE "STEP" = :step
               AND "STATUS" = :status
               AND "TOKEN" = ANY(:tokens)
            """)
    Set<UUID> getTokensByStepAndStateAndTokenAnyOf(
            @Bind WorkflowStep step,
            @Bind WorkflowStatus status,
            @Bind Collection<UUID> tokens);

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
             WHERE "ID" = ANY(SELECT "ID" FROM "CTE_CHILDREN")
            """)
    void cancelAllChildren(@Bind WorkflowStep step, @Bind("token") List<UUID> tokens);

    /**
     * @since 5.6.0
     */
    @SqlBatch("""
            WITH RECURSIVE
            "CTE_CHILDREN" ("ID") AS (
              SELECT "ID"
                FROM "WORKFLOW_STATE"
               WHERE "PARENT_STEP_ID" = :parentId
               UNION ALL
              SELECT "CHILD"."ID"
                FROM "WORKFLOW_STATE" AS "CHILD"
               INNER JOIN "CTE_CHILDREN" AS "PARENT"
                  ON "PARENT"."ID" = "CHILD"."PARENT_STEP_ID"
            )
            UPDATE "WORKFLOW_STATE"
               SET "STATUS" = 'CANCELLED'
                 , "UPDATED_AT" = NOW()
             WHERE "ID" = ANY(SELECT "ID" FROM "CTE_CHILDREN")
            """)
    int[] cancelAllChildrenByParentStepIdAnyOf(@Bind("parentId") List<Long> parentIds);

    /**
     * @since 5.6.0
     */
    @SqlUpdate("""
            UPDATE "WORKFLOW_STATE"
               SET "STATUS" = 'TIMED_OUT'
                 , "UPDATED_AT" = NOW()
             WHERE "STATUS" = 'PENDING'
               AND "UPDATED_AT" < (NOW() - :timeoutDuration)
            """)
    int transitionAllPendingStepsToTimedOutForTimeout(@Bind Duration timeoutDuration);

    /**
     * @since 5.6.0
     */
    default List<Long> transitionAllTimedOutStepsToFailedForTimeout(final Duration timeoutDuration) {
        // NB: Can't use interface method here due to https://github.com/jdbi/jdbi/issues/1807.
        return getHandle().createUpdate("""
                        UPDATE "WORKFLOW_STATE"
                           SET "STATUS" = 'FAILED'
                             , "FAILURE_REASON" = 'Timed out'
                             , "UPDATED_AT" = NOW()
                         WHERE "STATUS" = 'TIMED_OUT'
                           AND "UPDATED_AT" < (NOW() - :timeoutDuration)
                        RETURNING "ID"
                        """)
                .bind("timeoutDuration", timeoutDuration)
                .executeAndReturnGeneratedKeys()
                .mapTo(Long.class)
                .list();
    }

    /**
     * @since 5.6.0
     */
    @SqlUpdate("""
            WITH "CTE_ELIGIBLE_TOKENS" AS (
              SELECT "TOKEN"
                FROM "WORKFLOW_STATE" AS "WFS_PARENT"
               WHERE NOT EXISTS(
                 SELECT 1
                   FROM "WORKFLOW_STATE" AS "WFS"
                  WHERE "WFS"."TOKEN" = "WFS_PARENT"."TOKEN"
                    AND "WFS"."STATUS" IN ('PENDING', 'TIMED_OUT'))
               GROUP BY "TOKEN"
              HAVING MAX("UPDATED_AT") < (NOW() - :retentionDuration)
            )
            DELETE
              FROM "WORKFLOW_STATE"
             WHERE "TOKEN" = ANY(SELECT "TOKEN" FROM "CTE_ELIGIBLE_TOKENS")
            """)
    int deleteAllForRetention(@Bind Duration retentionDuration);

    /**
     * @since 5.6.0
     */
    @SqlQuery("""
            SELECT EXISTS(
              SELECT 1
                FROM "WORKFLOW_STATE"
               WHERE "TOKEN" = :token
                 AND "STATUS" IN ('PENDING', 'TIMED_OUT'))
            """)
    boolean existsWithNonTerminalStatus(@Bind UUID token);

}
