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
import org.dependencytrack.model.ProjectRole;
import org.dependencytrack.persistence.jdbi.mapping.ProjectRoleRowMapper;

import org.jdbi.v3.sqlobject.config.RegisterFieldMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import alpine.model.UserPrincipal;

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
            <#-- @ftlvariable name="user" type="alpine.model.UserPrincipal" -->
            <#assign prefix = user.getClass().getSimpleName()?upper_case>
            INSERT INTO "${prefix}S_PROJECTS_ROLES"
              ("${prefix}_ID", "PROJECT_ID", "ROLE_ID")
            VALUES
              (${user.getId()}, :projectId, :roleId)
            ON CONFLICT DO NOTHING
            """)
    @DefineNamedBindings
    <T extends UserPrincipal> int addRoleToUser(@Define T user, @Bind long projectId, @Bind long roleId);

    @SqlUpdate(/* language=sql */ """
            <#-- @ftlvariable name="user" type="alpine.model.UserPrincipal" -->
            <#-- @ftlvariable name="project" type="org.dependencytrack.model.Project" -->
            <#assign prefix = user.getClass().getSimpleName()?upper_case>
            DELETE
              FROM "${prefix}S_PROJECTS_ROLES"
             WHERE "${prefix}_ID" = ${user.getId()}
               AND "ROLE_ID" = :roleId
               AND "PROJECT_ID" IN (
                 SELECT "ID"
                   FROM "PROJECT"
                  WHERE "NAME" = '${project.getName()}'
               )
            """)
    @DefineNamedBindings
    <T extends UserPrincipal> int removeRoleFromUser(@Define T user, @Define Project project, @Bind long roleId);
    // (@Bind long userId, @Bind String projectName, @Bind long roleId)

    @SqlQuery(/* language=sql */ """
            <#-- @ftlvariable name="user" type="alpine.model.UserPrincipal" -->
            <#assign prefix = user.getClass().getSimpleName()?upper_case>
            SELECT
                "PROJECT"."ID"   AS "PROJECT_ID",
                "PROJECT"."NAME" AS "PROJECT_NAME",
                "PROJECT"."UUID" AS "PROJECT_UUID",
                "ROLE"."ID"      AS "ROLE_ID",
                "ROLE"."NAME"    AS "ROLE_NAME",
                "ROLE"."UUID"    AS "ROLE_UUID",
                "${prefix}"."ID" AS "${prefix}_ID"
              FROM "PROJECT"
             INNER JOIN "${prefix}S_PROJECTS_ROLES"
                ON "${prefix}S_PROJECTS_ROLES"."PROJECT_ID" = "PROJECT"."ID"
             INNER JOIN "${prefix}"
                ON "${prefix}"."ID" = "${prefix}S_PROJECTS_ROLES"."${prefix}_ID"
             INNER JOIN "ROLE"
                ON "ROLE"."ID" = "${prefix}S_PROJECTS_ROLES"."ROLE_ID"
             WHERE "${prefix}"."USERNAME" = '${user.getUsername()}'
            """)
    @RegisterRowMapper(ProjectRoleRowMapper.class)
    @DefineNamedBindings
    <T extends UserPrincipal> List<ProjectRole> getUserRoles(@Define T user);

    @SqlQuery(/* language=sql */ """
            <#-- @ftlvariable name="user" type="alpine.model.UserPrincipal" -->
            <#assign prefix = user.getClass().getSimpleName()?upper_case>
            SELECT "PROJECT"."ID", "PROJECT"."NAME", "PROJECT"."UUID"
              FROM "PROJECT"
              LEFT JOIN "${prefix}S_PROJECTS_ROLES"
                ON "${prefix}S_PROJECTS_ROLES"."PROJECT_ID" = "PROJECT"."ID"
              LEFT JOIN "${prefix}"
                ON "${prefix}"."ID" = "${prefix}S_PROJECTS_ROLES"."${prefix}_ID"
             WHERE "${prefix}"."USERNAME" != '${user.getUsername()}'
                OR "${prefix}"."USERNAME" IS NULL
            """)
    @RegisterFieldMapper(Project.class)
    <T extends UserPrincipal> List<Project> getUserUnassignedProjects(@Define T user);

}
