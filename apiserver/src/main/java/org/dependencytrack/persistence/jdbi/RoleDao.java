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

import java.util.List;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectRoleBinding;
import org.dependencytrack.persistence.jdbi.mapping.ProjectRoleRowBindingMapper;

import org.jdbi.v3.sqlobject.config.RegisterFieldMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

/**
 * @since 5.6.0
 */
public interface RoleDao {

    @SqlUpdate(/* language=sql */ """
            DELETE
              FROM "ROLE"
             WHERE "ID" = :roleId
            """)
    int deleteRole(@Bind final long roleId);

    @SqlUpdate(/* language=sql */ """
            INSERT INTO "ROLES_PERMISSIONS"
              ("ROLE_ID", "PERMISSION_ID")
            VALUES
              (:roleId, :permissionId)
            ON CONFLICT DO NOTHING
            """)
    int addPermissionToRole(@Bind long roleId, @Bind long permissionId);

    @SqlUpdate(/* language=sql */ """
            INSERT INTO "PROJECT_ROLE_BINDING"
              ("USER_ID", "PROJECT_ID", "ROLE_ID")
            VALUES
              (:userId, :projectId, :roleId)
            ON CONFLICT ("USER_ID", "PROJECT_ID") DO
            UPDATE SET "ROLE_ID" = EXCLUDED."ROLE_ID"
            """)
    int addRoleToUser(@Bind long userId, @Bind long projectId, @Bind long roleId);

    @SqlUpdate(/* language=sql */ """
            DELETE
              FROM "PROJECT_ROLE_BINDING"
             WHERE "USER_ID" = :userId
               AND "ROLE_ID" = :roleId
               AND "PROJECT_ID" IN (
                 SELECT "ID"
                   FROM "PROJECT"
                  WHERE "NAME" = :projectName
               )
            """)
    int removeRoleFromUser(@Bind long userId, @Bind String projectName, @Bind long roleId);

    @SqlQuery(/* language=sql */ """
            SELECT
                p."ID"       AS "PROJECT_ID",
                p."NAME"     AS "PROJECT_NAME",
                p."UUID"     AS "PROJECT_UUID",
                r."ID"       AS "ROLE_ID",
                r."NAME"     AS "ROLE_NAME",
                r."UUID"     AS "ROLE_UUID",
                u."ID"       AS "USER_ID",
                u."USERNAME" AS "USER_NAME",
                u."TYPE"     AS "USER_TYPE"
              FROM "PROJECT" p
             INNER JOIN "PROJECT_ROLE_BINDING" pr
                ON pr."PROJECT_ID" = p."ID"
             INNER JOIN "USER" u
                ON u."ID" = pr."USER_ID"
             INNER JOIN "ROLE" r
                ON r."ID" = pr."ROLE_ID"
             WHERE u."USERNAME" = :username
            """)
    @RegisterRowMapper(ProjectRoleRowBindingMapper.class)
    List<ProjectRoleBinding> getUserRoles(@Bind String username);

    @SqlQuery(/* language=sql */ """
            SELECT EXISTS (
              SELECT 1
                FROM "PROJECT_ROLE_BINDING"
               WHERE "ROLE_ID" = :roleId
                 AND "PROJECT_ID" = :projectId
                 AND "USER_ID" = :userId
            )
            """)
    boolean userProjectRoleBindingExists(@Bind long userId, @Bind long projectId, @Bind long roleId);

    @SqlQuery(/* language=sql */ """
            SELECT p."ID", p."NAME", p."UUID"
              FROM "PROJECT" p
              LEFT JOIN "PROJECT_ROLE_BINDING" pr
                ON pr."PROJECT_ID" = p."ID"
              LEFT JOIN "USER" u
                ON u."ID" = pr."USER_ID"
             WHERE u."USERNAME" != :username
                OR u."USERNAME" IS NULL
            """)
    @RegisterFieldMapper(Project.class)
    List<Project> getUserUnassignedProjects(@Bind String username);

}
