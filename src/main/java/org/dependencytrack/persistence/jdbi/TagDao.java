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

import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMappers;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;
import java.util.UUID;

@RegisterConstructorMappers({
        @RegisterConstructorMapper(TagDao.TaggedProjectRow.class),
        @RegisterConstructorMapper(TagDao.TagListRow.class),
})
public interface TagDao {

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "NAME" AS "name"
                 , (SELECT COUNT(*)
                      FROM "PROJECTS_TAGS"
                     INNER JOIN "PROJECT"
                        ON "PROJECT"."ID" = "PROJECTS_TAGS"."PROJECT_ID"
                     WHERE "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                       AND ${apiProjectAclCondition}
                   ) AS "projectCount"
                 , (SELECT COUNT(*)
                      FROM "POLICY_TAGS"
                     WHERE "POLICY_TAGS"."TAG_ID" = "TAG"."ID"
                   ) AS "policyCount"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "TAG"
            <#if apiFilterParameter??>
             WHERE "NAME" LIKE ('%' || ${apiFilterParameter} || '%')
            </#if>
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name" ASC, "ID" ASC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = "ID", by = {
            @AllowApiOrdering.Column(name = "ID"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "projectCount"),
            @AllowApiOrdering.Column(name = "policyCount")
    })
    List<TagListRow> getTags();

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "UUID" AS "uuid"
                 , "NAME" AS "name"
                 , "VERSION" AS "version"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "PROJECT"
             INNER JOIN "PROJECTS_TAGS"
                ON "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
             INNER JOIN "TAG"
                ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
             WHERE "TAG"."NAME" = :tag
               AND ${apiProjectAclCondition}
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name" ASC, "version" DESC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = "ID", by = {
            @AllowApiOrdering.Column(name = "ID"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version")
    })
    List<TaggedProjectRow> getTaggedProjects(@Bind String tag);

    record TagListRow(String name, int projectCount, int policyCount, int totalCount) {
    }

    record TaggedProjectRow(UUID uuid, String name, String version, int totalCount) {
    }

}
