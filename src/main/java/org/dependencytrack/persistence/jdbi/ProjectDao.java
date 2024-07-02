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
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import javax.annotation.Nullable;
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
                 , "PROJECT"."ACTIVE" AS "active"
                 , (SELECT ARRAY_AGG("TAG"."NAME")
                      FROM "TAG"
                     INNER JOIN "PROJECTS_TAGS"
                        ON "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                     WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID") AS "tags"
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
             WHERE ${apiProjectAclCondition!"TRUE"}
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
            <#if activeFilter>
               AND "PROJECT"."ACTIVE" = :activeFilter
            </#if>
            <#if onlyRootFilter>
               AND (NOT :onlyRootFilter OR "PROJECT"."PARENT_PROJECT_ID" IS NULL)
            <#elseif parentUuidFilter>
               AND EXISTS(
                     SELECT 1
                       FROM "PROJECT" AS "PARENT_PROJECT"
                      WHERE "PARENT_PROJECT"."ID" = "PROJECT"."PARENT_PROJECT_ID"
                        AND "PARENT_PROJECT"."UUID" = :parentUuidFilter
                        AND ${apiParentProjectAclCondition!"TRUE"})
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
            projectTableAlias = "PARENT_PROJECT"
    )
    @AllowApiOrdering(alwaysBy = "id", by = {
            @AllowApiOrdering.Column(name = "id"),
            @AllowApiOrdering.Column(name = "group"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version"),
            @AllowApiOrdering.Column(name = "classifier"),
            @AllowApiOrdering.Column(name = "lastBomImport"),
            @AllowApiOrdering.Column(name = "lastBomImportFormat"),
            @AllowApiOrdering.Column(name = "metrics.components", queryName = "\"metrics\".\"COMPONENTS\""),
            @AllowApiOrdering.Column(name = "metrics.inheritedRiskScore", queryName = "\"metrics\".\"RISKSCORE\""),
            @AllowApiOrdering.Column(name = "metrics.vulnerabilities", queryName = "\"metrics\".\"VULNERABILITIES\"")
    })
    List<ConciseProjectListRow> getPageConcise(
            @Bind String nameFilter,
            @Bind String classifierFilter,
            @Bind String tagFilter,
            @Bind Boolean activeFilter,
            @Bind Boolean onlyRootFilter,
            @Bind String parentUuidFilter,
            @Define boolean includeMetrics
    );

    record ConciseProjectListRow(
            UUID uuid,
            String group,
            String name,
            String version,
            String classifier,
            boolean active,
            List<String> tags,
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

}
