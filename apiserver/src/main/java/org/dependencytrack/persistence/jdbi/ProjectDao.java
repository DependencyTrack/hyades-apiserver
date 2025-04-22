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

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.annotation.Nullable;
import org.jdbi.v3.core.mapper.reflect.ColumnName;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * @since 5.5.0
 */
@RegisterConstructorMapper(ProjectDao.ConciseProjectListRow.class)
public interface ProjectDao {

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="nameFilter" type="Boolean" -->
            <#-- @ftlvariable name="classifierFilter" type="Boolean" -->
            <#-- @ftlvariable name="tagFilter" type="Boolean" -->
            <#-- @ftlvariable name="teamFilter" type="Boolean" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="onlyRootFilter" type="Boolean" -->
            <#-- @ftlvariable name="parentUuidFilter" type="Boolean" -->
            <#-- @ftlvariable name="includeMetrics" type="Boolean" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiParentProjectAclCondition" type="String" -->
            SELECT "PROJECT"."ID" AS "id"
                 , "PROJECT"."UUID" AS "uuid"
                 , "GROUP" AS "group"
                 , "NAME" AS "name"
                 , "VERSION" AS "version"
                 , "PROJECT"."CLASSIFIER" AS "classifier"
                 , "PROJECT"."INACTIVE_SINCE" AS "inactiveSince"
                 , "PROJECT"."IS_LATEST" AS "isLatest"
                 , (SELECT ARRAY_AGG("TAG"."NAME")
                      FROM "TAG"
                     INNER JOIN "PROJECTS_TAGS"
                        ON "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                     WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID") AS "tags"
                 , (SELECT ARRAY_AGG("TEAM"."NAME")
                      FROM "TEAM"
                     INNER JOIN "PROJECT_ACCESS_TEAMS"
                        ON "PROJECT_ACCESS_TEAMS"."TEAM_ID" = "TEAM"."ID"
                     WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID") AS "teams"
                 , "PROJECT"."LAST_BOM_IMPORTED" AS "lastBomImport"
                 , "PROJECT"."LAST_BOM_IMPORTED_FORMAT" AS "lastBomImportFormat"
                 , (SELECT EXISTS(
                     SELECT 1
                       FROM "PROJECT" AS "CHILD_PROJECT"
                      WHERE "CHILD_PROJECT"."PARENT_PROJECT_ID" = "PROJECT"."ID")) AS "hasChildren"
            <#if includeMetrics>
                 , TO_JSONB("metrics") AS "metrics"
            </#if>
                 , COUNT(*) OVER() AS "totalCount"
              FROM "PROJECT"
            <#if includeMetrics>
              LEFT JOIN LATERAL (
                SELECT "COMPONENTS"
                     , "CRITICAL"
                     , "HIGH"
                     , "LOW"
                     , "MEDIUM"
                     , "POLICYVIOLATIONS_FAIL"
                     , "POLICYVIOLATIONS_INFO"
                     , "POLICYVIOLATIONS_LICENSE_TOTAL"
                     , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
                     , "POLICYVIOLATIONS_SECURITY_TOTAL"
                     , "POLICYVIOLATIONS_TOTAL"
                     , "POLICYVIOLATIONS_WARN"
                     , "RISKSCORE"
                     , "UNASSIGNED_SEVERITY"
                     , "VULNERABILITIES"
                  FROM "PROJECTMETRICS"
                 WHERE "PROJECTMETRICS"."PROJECT_ID" = "PROJECT"."ID"
                 ORDER BY "PROJECTMETRICS"."LAST_OCCURRENCE" DESC
                 LIMIT 1
              ) AS "metrics" ON TRUE
            </#if>
             WHERE ${apiProjectAclCondition}
            <#if nameFilter>
               AND "PROJECT"."NAME" = :nameFilter
            </#if>
            <#if classifierFilter>
               AND "PROJECT"."CLASSIFIER" = :classifierFilter
            </#if>
            <#if tagFilter>
               AND EXISTS(
                 SELECT 1
                   FROM "PROJECTS_TAGS"
                  INNER JOIN "TAG"
                     ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                  WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                    AND "TAG"."NAME" = :tagFilter)
            </#if>
            <#if teamFilter>
               AND EXISTS(
                 SELECT 1
                   FROM "PROJECT_ACCESS_TEAMS"
                  INNER JOIN "TEAM"
                     ON "TEAM"."ID" = "PROJECT_ACCESS_TEAMS"."TEAM_ID"
                  WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                    AND "TEAM"."NAME" = :teamFilter)
            </#if>
            <#if activeFilter && activeFilter == true>
                AND "PROJECT"."INACTIVE_SINCE" IS NULL
            </#if>
            <#if onlyRootFilter>
               AND (NOT :onlyRootFilter OR "PROJECT"."PARENT_PROJECT_ID" IS NULL)
            <#elseif parentUuidFilter>
               AND EXISTS(
                     SELECT 1
                       FROM "PROJECT" AS "PARENT_PROJECT"
                      WHERE "PARENT_PROJECT"."ID" = "PROJECT"."PARENT_PROJECT_ID"
                        AND "PARENT_PROJECT"."UUID" = :parentUuidFilter
                        AND ${apiParentProjectAclCondition})
            </#if>
            <#if apiFilterParameter??>
               AND (LOWER("PROJECT"."NAME") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
                    OR EXISTS (SELECT 1 FROM "TAG" WHERE "TAG"."NAME" = ${apiFilterParameter}))
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            <#else>
             ORDER BY "name" ASC, "version" DESC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @DefineNamedBindings
    @DefineApiProjectAclCondition(
            name = "apiParentProjectAclCondition",
            projectIdColumn = "\"PARENT_PROJECT\".\"ID\""
    )
    @AllowApiOrdering(alwaysBy = "id", by = {
            @AllowApiOrdering.Column(name = "id"),
            @AllowApiOrdering.Column(name = "group"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version"),
            @AllowApiOrdering.Column(name = "classifier"),
            @AllowApiOrdering.Column(name = "inactiveSince"),
            @AllowApiOrdering.Column(name = "isLatest"),
            @AllowApiOrdering.Column(name = "lastBomImport"),
            @AllowApiOrdering.Column(name = "lastBomImportFormat"),
            @AllowApiOrdering.Column(name = "metrics.components", queryName = "\"metrics\".\"COMPONENTS\""),
            @AllowApiOrdering.Column(name = "metrics.inheritedRiskScore", queryName = "\"metrics\".\"RISKSCORE\""),
            @AllowApiOrdering.Column(name = "metrics.policyViolationsTotal", queryName = "\"metrics\".\"POLICYVIOLATIONS_TOTAL\""),
            @AllowApiOrdering.Column(name = "metrics.vulnerabilities", queryName = "\"metrics\".\"VULNERABILITIES\"")
    })
    List<ConciseProjectListRow> getPageConcise(
            @Bind String nameFilter,
            @Bind String classifierFilter,
            @Bind String tagFilter,
            @Bind String teamFilter,
            @Bind Boolean activeFilter,
            @Bind Boolean onlyRootFilter,
            @Bind UUID parentUuidFilter,
            @Define boolean includeMetrics
    );

    record ConciseProjectListRow(
            UUID uuid,
            String group,
            String name,
            String version,
            String classifier,
            @Nullable Instant inactiveSince,
            boolean isLatest,
            List<String> tags,
            List<String> teams,
            @Nullable Instant lastBomImport,
            @Nullable String lastBomImportFormat,
            boolean hasChildren,
            @Nullable @Json ConciseProjectMetricsRow metrics,
            long totalCount
    ) {
    }

    record ConciseProjectMetricsRow(
            int components,
            int critical,
            int high,
            int low,
            int medium,
            @JsonAlias("policyviolations_fail") int policyViolationsFail,
            @JsonAlias("policyviolations_info") int policyViolationsInfo,
            @JsonAlias("policyviolations_license_total") int policyViolationsLicenseTotal,
            @JsonAlias("policyviolations_operational_total") int policyViolationsOperationalTotal,
            @JsonAlias("policyviolations_security_total") int policyViolationsSecurityTotal,
            @JsonAlias("policyviolations_total") int policyViolationsTotal,
            @JsonAlias("policyviolations_warn") int policyViolationsWarn,
            @JsonAlias("riskscore") double riskScore,
            @JsonAlias("unassigned_severity") int unassigned,
            int vulnerabilities
    ) {
    }

    @SqlUpdate("""
            DELETE
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    int deleteProject(@Bind final UUID projectUuid);

    @SqlQuery("""
            WITH "CTE" AS (
              SELECT "ID"
                FROM "PROJECT"
               WHERE "INACTIVE_SINCE" < :retentionCutOff
               ORDER BY "INACTIVE_SINCE"
               LIMIT :batchSize
            )
            DELETE
              FROM "PROJECT"
             WHERE "ID" IN (SELECT "ID" FROM "CTE")
             RETURNING "NAME", "VERSION", "INACTIVE_SINCE", "UUID"
           """)
    @RegisterConstructorMapper(DeletedProject.class)
    List<DeletedProject> deleteInactiveProjectsForRetentionDuration(@Bind final Instant retentionCutOff, @Bind final int batchSize);

    record DeletedProject(@ColumnName("NAME") String name,
                          @ColumnName("VERSION") String version,
                          @ColumnName("INACTIVE_SINCE") Instant inactiveSince,
                          @ColumnName("UUID") UUID uuid) {
    }

    @SqlQuery("""
           DELETE
            FROM "PROJECT"
            WHERE "PROJECT"."INACTIVE_SINCE" IS NOT NULL
            AND "PROJECT"."NAME" = :projectName
            AND "PROJECT"."ID" NOT IN (
                SELECT "PROJECT"."ID" 
                 FROM "PROJECT"
                 WHERE "PROJECT"."INACTIVE_SINCE" IS NOT NULL
                 AND "PROJECT"."NAME" = :projectName
                 ORDER BY "PROJECT"."INACTIVE_SINCE" DESC
                 LIMIT :versionCountThreshold
                )
            RETURNING "NAME", "VERSION", "INACTIVE_SINCE", "UUID"
            """)
    @RegisterConstructorMapper(DeletedProject.class)
    List<DeletedProject> retainLastXInactiveProjects(@Bind final String projectName, @Bind final int versionCountThreshold);

    @SqlQuery("""
            SELECT "PROJECT"."NAME"
              FROM "PROJECT"
              WHERE "INACTIVE_SINCE" IS NOT NULL
              GROUP BY "NAME"
              HAVING COUNT(*) > :versionCountThreshold
              LIMIT :batchSize
            """)
    List<String> getDistinctProjects(@Bind final int versionCountThreshold, @Bind final int batchSize);

    @SqlQuery("""
            SELECT "ID" FROM "PROJECT" WHERE "UUID" = :projectUuid
            """)
    Long getProjectId(@Bind UUID projectUuid);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT ${apiProjectAclCondition}
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    Boolean isAccessible(@Bind UUID projectUuid);
}
