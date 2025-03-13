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

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.persistence.jdbi.mapping.FindingRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.GroupedFindingRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.AllowUnusedBindings;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public interface FindingDao {

    @SqlQuery("""
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME"
                 , "COMPONENT"."GROUP"
                 , "COMPONENT"."VERSION"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE"
                 , "VULNERABILITY"."UUID"
                 , "VULNERABILITY"."SOURCE"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE"
                 , "VULNERABILITY"."SUBTITLE"
                 , "VULNERABILITY"."DESCRIPTION"
                 , "VULNERABILITY"."RECOMMENDATION"
                 , "VULNERABILITY"."SEVERITY"
                 , CAST(STRING_TO_ARRAY("VULNERABILITY"."CWES", ',') AS INT[]) AS "CWES"
                 , "VULNERABILITY"."CVSSV2BASESCORE"
                 , "VULNERABILITY"."CVSSV3BASESCORE"
                 , "VULNERABILITY"."CVSSV2VECTOR"
                 , "VULNERABILITY"."CVSSV3VECTOR"
                 , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                 , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRVECTOR"
                 , "EPSS"."SCORE"
                 , "EPSS"."PERCENTILE"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE"
                 , "ANALYSIS"."SUPPRESSED"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
              LEFT JOIN "EPSS"
                ON "VULNERABILITY"."VULNID" = "EPSS"."CVE"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS"
                ON "COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
              INNER JOIN "PROJECT"
                ON "COMPONENT"."PROJECT_ID" = "PROJECT"."ID"
             WHERE "COMPONENT"."PROJECT_ID" = :projectId
               AND (:includeSuppressed OR "ANALYSIS"."SUPPRESSED" IS NULL OR NOT "ANALYSIS"."SUPPRESSED")
            """)
    @RegisterRowMapper(FindingRowMapper.class)
    List<Finding> getFindings(@Bind long projectId, @Bind boolean includeSuppressed);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="queryFilter" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="suppressedFilter" type="Boolean" -->
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "PROJECT"."NAME" AS "projectName"
                 , "PROJECT"."VERSION" AS "projectVersion"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME"
                 , "COMPONENT"."GROUP"
                 , "COMPONENT"."VERSION"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE"
                 , "VULNERABILITY"."UUID"
                 , "VULNERABILITY"."SOURCE"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE"
                 , "VULNERABILITY"."SUBTITLE"
                 , "VULNERABILITY"."DESCRIPTION"
                 , "VULNERABILITY"."RECOMMENDATION"
                 , "VULNERABILITY"."PUBLISHED"
                 , "VULNERABILITY"."SEVERITY"
                 , CAST(STRING_TO_ARRAY("VULNERABILITY"."CWES", ',') AS INT[]) AS "CWES"
                 , "VULNERABILITY"."CVSSV2BASESCORE"
                 , "VULNERABILITY"."CVSSV3BASESCORE"
                 , "VULNERABILITY"."CVSSV2VECTOR"
                 , "VULNERABILITY"."CVSSV3VECTOR"
                 , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                 , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRVECTOR"
                 , JSONB_VULN_ALIASES("VULNERABILITY"."SOURCE", "VULNERABILITY"."VULNID") AS "vulnAliasesJson"
                 , "EPSS"."SCORE"
                 , "EPSS"."PERCENTILE"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE"
                 , "ANALYSIS"."SUPPRESSED"
                 , "REPOSITORY_META_COMPONENT"."LATEST_VERSION" AS "latest_version"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
             LEFT JOIN "EPSS"
                ON "VULNERABILITY"."VULNID" = "EPSS"."CVE"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS"
                ON "COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
              LEFT JOIN "REPOSITORY_META_COMPONENT"
                ON "COMPONENT"."NAME" = "REPOSITORY_META_COMPONENT"."NAME"
             INNER JOIN "PROJECT"
                ON "COMPONENT"."PROJECT_ID" = "PROJECT"."ID"
             WHERE ${apiProjectAclCondition}
             <#if !activeFilter>
                AND "PROJECT"."INACTIVE_SINCE" IS NULL
             </#if>
             <#if !suppressedFilter>
                AND "ANALYSIS"."SUPPRESSED" IS NULL OR "ANALYSIS"."SUPPRESSED" = false
             </#if>
             <#if queryFilter??>
                ${queryFilter}
             </#if>
             <#if apiOrderByClause??>
              ${apiOrderByClause}
             </#if>
            """)
    @RegisterRowMapper(FindingRowMapper.class)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "\"VULNERABILITY\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "\"VULNERABILITY\".\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"VULNERABILITY\".\"SEVERITY\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"VULNERABILITY\".\"CVSSV3BASESCORE\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"VULNERABILITY\".\"CVSSV2BASESCORE\""),
            @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "\"VULNERABILITY\".\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "component.projectName", queryName = "concat(\"PROJECT\".\"NAME\", ' ', \"PROJECT\".\"VERSION\")"),
            @AllowApiOrdering.Column(name = "component.name", queryName = "\"COMPONENT\".\"NAME\""),
            @AllowApiOrdering.Column(name = "component.version", queryName = "\"COMPONENT\".\"VERSION\""),
            @AllowApiOrdering.Column(name = "analysis.state", queryName = "\"ANALYSIS\".\"STATE\""),
            @AllowApiOrdering.Column(name = "analysis.isSuppressed", queryName = "\"ANALYSIS\".\"SUPPRESSED\""),
            @AllowApiOrdering.Column(name = "attribution.attributedOn", queryName = "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"")
    })
    @AllowUnusedBindings
    List<Finding> getAllFindings(@Define String queryFilter,
                                 @Define boolean activeFilter,
                                 @Define boolean suppressedFilter);

    @SqlQuery("""
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            SELECT "VULNERABILITY"."SOURCE"
                , "VULNERABILITY"."VULNID"
                , "VULNERABILITY"."TITLE"
                , "VULNERABILITY"."SEVERITY"
                , "VULNERABILITY"."CVSSV2BASESCORE"
                , "VULNERABILITY"."CVSSV3BASESCORE"
                , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                , "VULNERABILITY"."PUBLISHED"
                , CAST(STRING_TO_ARRAY("VULNERABILITY"."CWES", ',') AS INT[]) AS "CWES"
                , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                , COUNT(DISTINCT "PROJECT"."ID") AS "affectedProjectCount"
            FROM "COMPONENT"
                INNER JOIN "COMPONENTS_VULNERABILITIES"
                    ON ("COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID")
                INNER JOIN "VULNERABILITY"
                    ON ("COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID")
                INNER JOIN "FINDINGATTRIBUTION"
                    ON ("COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID")
                    AND ("VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID")
                LEFT JOIN "ANALYSIS"
                    ON ("COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID")
                    AND ("VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID")
                    AND ("COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID")
                INNER JOIN "PROJECT"
                    ON ("COMPONENT"."PROJECT_ID" = "PROJECT"."ID")
            WHERE ${apiProjectAclCondition}
            <#if !activeFilter>
                AND "PROJECT"."INACTIVE_SINCE" IS NULL
            </#if>
            <#if queryFilter??>
                ${queryFilter}
            </#if>
            GROUP BY "VULNERABILITY"."ID"
               , "VULNERABILITY"."SOURCE"
               , "VULNERABILITY"."VULNID"
               , "VULNERABILITY"."TITLE"
               , "VULNERABILITY"."SEVERITY"
               , "VULNERABILITY"."CVSSV2BASESCORE"
               , "VULNERABILITY"."CVSSV3BASESCORE"
               , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
               , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
               , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
               , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
               , "VULNERABILITY"."PUBLISHED"
               , "VULNERABILITY"."CWES"
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            </#if>
            """)
    @RegisterRowMapper(GroupedFindingRowMapper.class)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "\"VULNERABILITY\".\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "\"VULNERABILITY\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"VULNERABILITY\".\"SEVERITY\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"VULNERABILITY\".\"CVSSV3BASESCORE\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"VULNERABILITY\".\"CVSSV2BASESCORE\""),
            @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "\"VULNERABILITY\".\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "vulnerability.affectedProjectCount", queryName = "affectedProjectCount")
    })
    @AllowUnusedBindings
    List<GroupedFinding> getGroupedFindings(@Define String queryFilter, @Define boolean activeFilter);

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters. The resulting list is grouped by vulnerability.
     *
     * @param filters       determines the filters to apply on the list of Finding objects
     * @param showInactive  determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    default PaginatedResult getGroupedFindings(final AlpineRequest alpineRequest, final Map<String, String> filters, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        processFilters(filters, queryFilter);
        final List<GroupedFinding> findings = withJdbiHandle(alpineRequest, handle ->
                getGroupedFindings(String.valueOf(queryFilter), showInactive));
        PaginatedResult result = new PaginatedResult();
        result.setTotal(findings.size());
        final List<GroupedFinding> findingsList = findings.subList(alpineRequest.getPagination().getOffset(),
                Math.min(alpineRequest.getPagination().getOffset()
                        + alpineRequest.getPagination().getLimit(), findings.size()));
        result.setObjects(findingsList);
        return result;
    }

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters.
     * @param filters        determines the filters to apply on the list of Finding objects
     * @param showSuppressed determines if suppressed vulnerabilities should be included or not
     * @param showInactive   determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    default PaginatedResult getAllFindings(final AlpineRequest alpineRequest, final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        processFilters(filters, queryFilter);
        final List<Finding> findings = withJdbiHandle(handle ->
                getAllFindings(String.valueOf(queryFilter), showInactive, showSuppressed));
        PaginatedResult result = new PaginatedResult();
        result.setTotal(findings.size());
        final List<Finding> findingList = findings.subList(alpineRequest.getPagination().getOffset(),
                Math.min(alpineRequest.getPagination().getOffset() + alpineRequest.getPagination().getLimit(), findings.size()));
        result.setObjects(findingList);
        return result;
    }


    private void processFilters(Map<String, String> filters, StringBuilder queryFilter) {
        Map<String, Object> params = new HashMap<>();
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "severity" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"SEVERITY\"");
                case "analysisStatus" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"ANALYSIS\".\"STATE\"");
                case "vendorResponse" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"ANALYSIS\".\"RESPONSE\"");
                case "publishDateFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"PUBLISHED\"", true, true, false);
                case "publishDateTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"PUBLISHED\"", false, true, false);
                case "attributedOnDateFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"", true, true, false);
                case "attributedOnDateTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"", false, true, false);
                case "textSearchField" ->
                        processInputFilter(queryFilter, params, filter, filters.get(filter), filters.get("textSearchInput"));
                case "cvssv2From" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV2BASESCORE\"", true, false, false);
                case "cvssv2To" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV2BASESCORE\"", false, false, false);
                case "cvssv3From" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV3BASESCORE\"", true, false, false);
                case "cvssv3To" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV3BASESCORE\"", false, false, false);
            }
        }
    }

    private void processArrayFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column) {
        if (filter != null && !filter.isEmpty()) {
            queryFilter.append(" AND (");
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                queryFilter.append(column).append(" = :").append(paramName).append(i);
                params.put(paramName + i, filters[i].toUpperCase());
                if (filters[i].equals("NOT_SET") && (paramName.equals("analysisStatus") || paramName.equals("vendorResponse"))) {
                    queryFilter.append(" OR ").append(column).append(" IS NULL");
                }
                if (i < length - 1) {
                    queryFilter.append(" OR ");
                }
            }
            queryFilter.append(")");
        }
    }

    private void processRangeFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column, boolean fromValue, boolean isDate, boolean isAggregateFilter) {
        if (filter != null && !filter.isEmpty()) {
            queryFilter.append(" AND (");
            String value = filter;
            if (DbUtil.isPostgreSQL()) {
                queryFilter.append(column).append(fromValue ? " >= " : " <= ");
                if (isDate) {
                    queryFilter.append("TO_TIMESTAMP(:").append(paramName).append(", 'YYYY-MM-DD HH24:MI:SS')");
                    value += (fromValue ? " 00:00:00" : " 23:59:59");
                } else {
                    queryFilter.append("CAST(:").append(paramName).append(" AS NUMERIC)");
                }
            } else {
                queryFilter.append(column).append(fromValue ? " >= :" : " <= :").append(paramName);
                if (isDate) {
                    value += (fromValue ? " 00:00:00" : " 23:59:59");
                }
            }
            params.put(paramName, value);
            queryFilter.append(")");
        }
    }

    private void processInputFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String input) {
        if (filter != null && !filter.isEmpty() && input != null && !input.isEmpty()) {
            queryFilter.append(" AND (");
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                switch (filters[i].toUpperCase()) {
                    case "VULNERABILITY_ID" -> queryFilter.append("\"VULNERABILITY\".\"VULNID\"");
                    case "VULNERABILITY_TITLE" -> queryFilter.append("\"VULNERABILITY\".\"TITLE\"");
                    case "COMPONENT_NAME" -> queryFilter.append("\"COMPONENT\".\"NAME\"");
                    case "COMPONENT_VERSION" -> queryFilter.append("\"COMPONENT\".\"VERSION\"");
                    case "PROJECT_NAME" ->
                            queryFilter.append("concat(\"PROJECT\".\"NAME\", ' ', \"PROJECT\".\"VERSION\")");
                }
                queryFilter.append(" LIKE :").append(paramName);
                if (i < length - 1) {
                    queryFilter.append(" OR ");
                }
            }
            if (filters.length > 0) {
                params.put(paramName, "%" + input + "%");
            }
            queryFilter.append(")");
        }
    }
}
