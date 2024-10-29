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
package org.dependencytrack.workflow;

import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMappers;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMethods;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.List;
import java.util.UUID;

@RegisterConstructorMappers(value = {
        @RegisterConstructorMapper(Workflow.class),
        @RegisterConstructorMapper(WorkflowRun.class),
        @RegisterConstructorMapper(WorkflowStep.class),
        @RegisterConstructorMapper(WorkflowStepRun.class),
        @RegisterConstructorMapper(WorkflowRunView.class),
        @RegisterConstructorMapper(WorkflowStepRunView.class),
        @RegisterConstructorMapper(ClaimedWorkflowStepRun.class)})
public interface WorkflowDao extends SqlObject {

    @SqlUpdate("""
            INSERT INTO "WORKFLOW" (
              "NAME"
            , "VERSION"
            , "CREATED_AT"
            ) VALUES (
              :name
            , :version
            , NOW()
            )
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    Workflow createWorkflow(@BindMethods NewWorkflow newWorkflow);

    @SqlQuery("""
            SELECT *
              FROM "WORKFLOW"
             WHERE "NAME" = :name
               AND "VERSION" = :version
            """)
    Workflow getWorkflowByNameAndVersion(@Bind String name, @Bind int version);

    @SqlUpdate("""
            INSERT INTO "WORKFLOW_STEP" (
              "NAME"
            , "TYPE"
            , "WORKFLOW_ID"
            ) VALUES (
              :name
            , :type
            , :workflowId
            )
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    WorkflowStep createStep(@BindMethods NewWorkflowStep newWorkflowStep);

    @SqlQuery("""
            SELECT *
              FROM "WORKFLOW_STEP"
             WHERE "WORKFLOW_ID" = :id
            """)
    List<WorkflowStep> getStepsByWorkflow(@BindMethods Workflow workflow);

    @SqlUpdate("""
            INSERT INTO "WORKFLOW_STEP_DEPENDENCY" (
              "DEPENDANT_STEP_ID"
            , "DEPENDENCY_STEP_ID"
            ) VALUES (
              :dependantStepId
            , :dependencyStepId
            )
            """)
    void createStepDependency(@Bind long dependantStepId, @Bind long dependencyStepId);

    @SqlUpdate("""
            INSERT INTO "WORKFLOW_RUN" (
              "WORKFLOW_ID"
            , "TOKEN"
            , "STATUS"
            , "CREATED_AT"
            ) VALUES (
              :workflow.id
            , :token
            , 'PENDING'
            , NOW()
            )
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    WorkflowRun createWorkflowRun(@BindMethods("workflow") Workflow workflow, @Bind UUID token);

    @SqlUpdate("""
            INSERT INTO "WORKFLOW_STEP_RUN"(
              "WORKFLOW_RUN_ID"
            , "WORKFLOW_STEP_ID"
            , "STATUS"
            , "CREATED_AT"
            , "STARTED_AT"
            ) VALUES (
              :workflowRun.id
            , :step.id
            , 'PENDING'
            , NOW()
            , NULL
            )
            RETURNING *
            """)
    @GetGeneratedKeys("*")
    WorkflowStepRun createStepRun(@BindMethods("workflowRun") WorkflowRun workflowRun, @BindMethods("step") WorkflowStep step);

    @SqlQuery("""
            SELECT "WF"."NAME" AS "workflowName"
                 , "WF"."VERSION" AS "workflowVersion"
                 , "WFR"."TOKEN" AS "token"
                 , "WFR"."PRIORITY" AS "priority"
                 , "WFR"."STATUS" AS "status"
                 , "WFR"."CREATED_AT" AS "createdAt"
                 , "WFR"."STARTED_AT" AS "startedAt"
              FROM "WORKFLOW_RUN" AS "WFR"
             INNER JOIN "WORKFLOW" AS "WF"
                ON "WF"."ID" = "WFR"."WORKFLOW_ID"
             WHERE "WFR"."TOKEN" = :token
            """)
    WorkflowRunView getWorkflowRunViewByToken(@Bind UUID token);

    @SqlQuery("""
            SELECT "WFS"."NAME" AS "stepName"
                 , "WFS"."TYPE" AS "stepType"
                 , "WFSR"."STATUS" AS "status"
                 , "WFSR"."CREATED_AT" AS "createdAt"
                 , "WFSR"."STARTED_AT" AS "startedAt"
              FROM "WORKFLOW_RUN" AS "WFR"
             INNER JOIN "WORKFLOW_STEP_RUN" AS "WFSR"
                ON "WFSR"."WORKFLOW_RUN_ID" = "WFR"."ID"
             INNER JOIN "WORKFLOW_STEP" AS "WFS"
                ON "WFS"."ID" = "WFSR"."WORKFLOW_STEP_ID"
             WHERE "WFR"."TOKEN" = :token
            """)
    List<WorkflowStepRunView> getStepRunViewsByToken(@Bind UUID token);

    default List<ClaimedWorkflowStepRun> claimRunnableStepRuns(final UUID token, final String name) {
        return getHandle().createUpdate("""
                            WITH "CTE_STEP_RUN" AS (
                            SELECT "WFSR"."ID" AS "ID"
                                 , "WFS"."NAME" AS "NAME"
                                 , "WFS"."TYPE" AS "TYPE"
                                 , "WFR"."PRIORITY" AS "PRIORITY"
                               FROM "WORKFLOW_STEP_RUN" AS "WFSR"
                              INNER JOIN "WORKFLOW_RUN" AS "WFR"
                                 ON "WFR"."ID" = "WFSR"."WORKFLOW_RUN_ID"
                              INNER JOIN "WORKFLOW_STEP" AS "WFS"
                                 ON "WFS"."ID" = "WFSR"."WORKFLOW_STEP_ID"
                              WHERE "WFR"."TOKEN" = :token
                                AND (:name IS NULL OR "WFS"."NAME" = :name)
                                AND "WFSR"."STATUS" NOT IN ('COMPLETED', 'FAILED', 'RUNNING')
                                -- If the workflow run has dependencies, those have to complete first.
                                AND NOT EXISTS (
                                    SELECT *
                                      FROM "WORKFLOW_STEP_DEPENDENCY" AS "WFSD"
                                     INNER JOIN "WORKFLOW_STEP" AS "WFS2"
                                        ON "WFS2"."ID" = "WFSD"."DEPENDENCY_STEP_ID"
                                     INNER JOIN "WORKFLOW_STEP_RUN" AS "WFSR2"
                                        ON "WFSR2"."WORKFLOW_RUN_ID" = "WFR"."ID"
                                       AND "WFSR2"."WORKFLOW_STEP_ID" = "WFS2"."ID"
                                     WHERE "WFSD"."DEPENDANT_STEP_ID" = "WFS"."ID"
                                       AND "WFSR2"."STATUS" != 'COMPLETED')
                                FOR UPDATE OF "WFSR"
                               SKIP LOCKED
                              LIMIT 1)
                        UPDATE "WORKFLOW_STEP_RUN" AS "WFSR"
                           SET "STATUS" = 'RUNNING'
                             , "STARTED_AT" = NOW()
                           FROM "CTE_STEP_RUN"
                          WHERE "WFSR"."ID" = "CTE_STEP_RUN"."ID"
                        RETURNING "WFSR"."ID" AS "id"
                                , "WFSR"."WORKFLOW_STEP_ID" AS "stepId"
                                , "WFSR"."WORKFLOW_RUN_ID" AS "workflowRunId"
                                , :token AS "token"
                                , "CTE_STEP_RUN"."NAME" AS "stepName"
                                , "CTE_STEP_RUN"."TYPE" AS "stepType"
                                , "STATUS" AS "status"
                                , "CTE_STEP_RUN"."PRIORITY" AS "priority"
                        """)
                .bind("token", token)
                .bind("name", name)
                .executeAndReturnGeneratedKeys("*")
                .map(ConstructorMapper.of(ClaimedWorkflowStepRun.class))
                .list();
    }

    default ClaimedWorkflowStepRun claimRunnableStepRun(final UUID token, final String name) {
        final List<ClaimedWorkflowStepRun> claimedStepRuns = claimRunnableStepRuns(token, name);
        return !claimedStepRuns.isEmpty() ? claimedStepRuns.getFirst() : null;
    }

    @SqlQuery("""
            SELECT "WFSR"."ID" AS "ID"
              FROM "WORKFLOW_STEP_RUN" AS "WFSR"
             INNER JOIN "WORKFLOW_RUN" AS "WFR"
                ON "WFR"."ID" = "WFSR"."WORKFLOW_RUN_ID"
             INNER JOIN "WORKFLOW_STEP" AS "WFS"
                ON "WFS"."ID" = "WFSR"."WORKFLOW_STEP_ID"
             WHERE "WFR"."TOKEN" = :token
               AND "WFS"."NAME" = :stepName
               FOR UPDATE OF "WFSR"
              SKIP LOCKED
             LIMIT 1
            """)
    WorkflowStepRun getStepRunForUpdateByTokenAndName(@Bind UUID token, @Bind String name);

    @SqlUpdate("""
            WITH "CTE_RUN" AS (
                SELECT "WFR"."ID" AS "ID"
                  FROM "WORKFLOW_RUN" AS "WFR"
                 WHERE "WFR"."ID" = :id
                   FOR UPDATE OF "WFR"
                  SKIP LOCKED
                 LIMIT 1)
            UPDATE "WORKFLOW_RUN" AS "WFR"
               SET "STATUS" = :newStatus
                 , "UPDATED_AT" = NOW()
              FROM "CTE_RUN"
             WHERE "WFR"."ID" = "CTE_RUN"."ID"
            """)
    boolean transitionWorkflowRun(@Bind long id, @Bind WorkflowRunStatus newStatus);

    @SqlUpdate("""
            WITH "CTE_STEP_RUN" AS (
                SELECT "WFSR"."ID" AS "ID"
                  FROM "WORKFLOW_STEP_RUN" AS "WFSR"
                 WHERE "WFSR"."ID" = :id
                   FOR UPDATE OF "WFSR"
                  SKIP LOCKED
                 LIMIT 1)
            UPDATE "WORKFLOW_STEP_RUN" AS "WFSR"
               SET "STATUS" = :newStatus
                 , "UPDATED_AT" = NOW()
              FROM "CTE_STEP_RUN"
             WHERE "WFSR"."ID" = "CTE_STEP_RUN"."ID"
            """)
    boolean transitionStepRun(@Bind long id, @Bind WorkflowStepRunStatus newStatus);

    @SqlUpdate("""
            WITH RECURSIVE
            "CTE_DEPENDANT_STEPS" ("ID") AS (
                SELECT "WFS"."ID"
                  FROM "WORKFLOW_STEP_DEPENDENCY" AS "WFSD"
                 INNER JOIN "WORKFLOW_STEP" AS "WFS"
                    ON "WFS"."ID" = "WFSD"."DEPENDANT_STEP_ID"
                 WHERE "WFSD"."DEPENDENCY_STEP_ID" = :dependencyStepId
                 UNION ALL
                SELECT "WFS"."ID"
                  FROM "WORKFLOW_STEP_DEPENDENCY" AS "WFSD"
                 INNER JOIN "WORKFLOW_STEP" AS "WFS"
                    ON "WFS"."ID" = "WFSD"."DEPENDANT_STEP_ID"
                 INNER JOIN "CTE_DEPENDANT_STEPS"
                    ON "CTE_DEPENDANT_STEPS"."ID" = "WFSD"."DEPENDENCY_STEP_ID")
            UPDATE "WORKFLOW_STEP_RUN"
               SET "STATUS" = 'CANCELLED'
                 , "UPDATED_AT" = NOW()
             WHERE "WORKFLOW_STEP_ID" = ANY(SELECT "ID" FROM "CTE_DEPENDANT_STEPS")
               AND "WORKFLOW_RUN_ID" = :workflowRunId
            """)
    int cancelDependantStepRuns(@Bind long workflowRunId, @Bind long dependencyStepId);

}
