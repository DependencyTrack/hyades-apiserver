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

import alpine.server.util.DbUtil;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.AllowUnusedBindings;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMap;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.resources.v1.FindingResource.mapComponentLatestVersion;

public interface FindingDao {

    record FindingRow(
            UUID projectUuid,
            UUID componentUuid,
            String projectName,
            String projectVersion,
            String componentName,
            String componentGroup,
            String componentVersion,
            String componentPurl,
            String componentCpe,
            boolean componentHasOccurrences,
            UUID vulnUuid,
            Vulnerability.Source vulnSource,
            String vulnId,
            String vulnTitle,
            String vulnSubtitle,
            String vulnDescription,
            String vulnRecommendation,
            Instant vulnPublished,
            Severity vulnSeverity,
            List<Integer> cwes,
            BigDecimal cvssV2BaseScore,
            BigDecimal cvssV3BaseScore,
            String cvssV2Vector,
            String cvssV3Vector,
            BigDecimal owaspRRLikelihoodScore,
            BigDecimal owaspRRTechnicalImpactScore,
            BigDecimal owaspRRBusinessImpactScore,
            String owaspRRVector,
            @Json List<VulnerabilityAlias> vulnAliasesJson,
            BigDecimal epssScore,
            BigDecimal epssPercentile,
            AnalyzerIdentity analyzerIdentity,
            Instant attributed_on,
            String alt_id,
            String reference_url,
            AnalysisState analysisState,
            boolean suppressed,
            long totalCount
    ) {
    }

    record GroupedFindingRow(
            Vulnerability.Source vulnSource,
            String vulnId,
            String vulnTitle,
            Severity vulnSeverity,
            BigDecimal cvssV2BaseScore,
            BigDecimal cvssV3BaseScore,
            Instant vulnPublished,
            List<Integer> cwes,
            AnalyzerIdentity analyzerIdentity,
            int affectedProjectCount,
            long totalCount
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="includeSuppressed" type="boolean" -->
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "PROJECT"."NAME" AS "projectName"
                 , "PROJECT"."VERSION" AS "projectVersion"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME" AS "componentName"
                 , "COMPONENT"."GROUP" AS "componentGroup"
                 , "COMPONENT"."VERSION" AS "componentVersion"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE" AS "componentCpe"
                 , EXISTS(SELECT 1 FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = "COMPONENT"."ID") AS "componentHasOccurrences"
                 , "V"."UUID" AS "vulnUuid"
                 , "V"."SOURCE" AS "vulnSource"
                 , "V"."VULNID"
                 , "V"."TITLE" AS "vulnTitle"
                 , "V"."SUBTITLE" AS "vulnSubtitle"
                 , "V"."DESCRIPTION" AS "vulnDescription"
                 , "V"."RECOMMENDATION" AS "vulnRecommendation"
                 , "V"."PUBLISHED" AS "vulnPublished",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2SCORE"
                    ELSE "V"."CVSSV2BASESCORE"
                 END                              AS "cvssV2BaseScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3SCORE"
                    ELSE "V"."CVSSV3BASESCORE"
                 END                              AS "cvssV3BaseScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2VECTOR"
                    ELSE "V"."CVSSV2VECTOR"
                 END                              AS "cvssV2Vector",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3VECTOR"
                    ELSE "V"."CVSSV3VECTOR"
                 END                              AS "cvssV3Vector",
                  -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
                  --  How to handle this?
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                    ELSE "V"."OWASPRRBUSINESSIMPACTSCORE"
                 END                              AS "owaspRRBusinessImpactScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                    ELSE "V"."OWASPRRLIKELIHOODSCORE"
                 END                              AS "owaspRRLikelihoodScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                    ELSE "V"."OWASPRRTECHNICALIMPACTSCORE"
                 END                              AS "owaspRRTechnicalImpactScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPVECTOR"
                    ELSE "V"."OWASPRRVECTOR"
                 END                              AS "owaspRRVector",
                 COALESCE("A"."SEVERITY", "V"."SEVERITY") AS "vulnSeverity"
                 , CAST(STRING_TO_ARRAY("V"."CWES", ',') AS INT[]) AS "CWES"
                 , JSONB_VULN_ALIASES("V"."SOURCE", "V"."VULNID") AS "vulnAliasesJson"
                 , "EPSS"."SCORE" AS "epssScore"
                 , "EPSS"."PERCENTILE" AS "epssPercentile"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "A"."STATE" AS "analysisState"
                 , "A"."SUPPRESSED"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY" AS "V"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "V"."ID"
              LEFT JOIN "EPSS"
                ON "V"."VULNID" = "EPSS"."CVE"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "V"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS" AS "A"
                ON "COMPONENT"."ID" = "A"."COMPONENT_ID"
               AND "V"."ID" = "A"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "A"."PROJECT_ID"
              INNER JOIN "PROJECT"
                ON "COMPONENT"."PROJECT_ID" = "PROJECT"."ID"
             WHERE "COMPONENT"."PROJECT_ID" = :projectId
            <#if !includeSuppressed>
               AND "A"."SUPPRESSED" IS DISTINCT FROM TRUE
            </#if>
               AND (:hasAnalysis IS NULL OR ("A"."ID" IS NOT NULL) = :hasAnalysis)
             ORDER BY "FINDINGATTRIBUTION"."ID"
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(FindingRow.class)
    List<FindingRow> getFindingsByProject(@Bind long projectId, @Define boolean includeSuppressed, @Bind Boolean hasAnalysis);

    default List<Finding> getFindings(final long projectId, final boolean includeSuppressed) {
        List<FindingRow> findingRows = getFindingsByProject(projectId, includeSuppressed, null);
        List<Finding> findings = findingRows.stream().map(Finding::new).toList();
        findings = mapComponentLatestVersion(findings);
        return findings;
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="queryFilter" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="suppressedFilter" type="Boolean" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "PROJECT"."NAME" AS "projectName"
                 , "PROJECT"."VERSION" AS "projectVersion"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME" AS "componentName"
                 , "COMPONENT"."GROUP" AS "componentGroup"
                 , "COMPONENT"."VERSION" AS "componentVersion"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE" AS "componentCpe"
                 , EXISTS(SELECT 1 FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = "COMPONENT"."ID") AS "componentHasOccurrences"
                 , "V"."UUID" AS "vulnUuid"
                 , "V"."SOURCE" AS "vulnSource"
                 , "V"."VULNID"
                 , "V"."TITLE" AS "vulnTitle"
                 , "V"."SUBTITLE" AS "vulnSubtitle"
                 , "V"."DESCRIPTION" AS "vulnDescription"
                 , "V"."RECOMMENDATION" AS "vulnRecommendation"
                 , "V"."PUBLISHED" AS "vulnPublished",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2SCORE"
                    ELSE "V"."CVSSV2BASESCORE"
                 END                              AS "cvssV2BaseScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3SCORE"
                    ELSE "V"."CVSSV3BASESCORE"
                 END                              AS "cvssV3BaseScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2VECTOR"
                    ELSE "V"."CVSSV2VECTOR"
                 END                              AS "cvssV2Vector",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3VECTOR"
                    ELSE "V"."CVSSV3VECTOR"
                 END                              AS "cvssV3Vector",
                  -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
                  --  How to handle this?
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                    ELSE "V"."OWASPRRBUSINESSIMPACTSCORE"
                 END                              AS "owaspRRBusinessImpactScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                    ELSE "V"."OWASPRRLIKELIHOODSCORE"
                 END                              AS "owaspRRLikelihoodScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                    ELSE "V"."OWASPRRTECHNICALIMPACTSCORE"
                 END                              AS "owaspRRTechnicalImpactScore",
                 CASE
                    WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPVECTOR"
                    ELSE "V"."OWASPRRVECTOR"
                 END                              AS "owaspRRVector",
                 COALESCE("A"."SEVERITY", "V"."SEVERITY") AS "vulnSeverity"
                 , CAST(STRING_TO_ARRAY("V"."CWES", ',') AS INT[]) AS "CWES"
                 , JSONB_VULN_ALIASES("V"."SOURCE", "V"."VULNID") AS "vulnAliasesJson"
                 , "EPSS"."SCORE" AS "epssScore"
                 , "EPSS"."PERCENTILE" AS "epssPercentile"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "A"."STATE" AS "analysisState"
                 , "A"."SUPPRESSED"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY" AS "V"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "V"."ID"
             LEFT JOIN "EPSS"
                ON "V"."VULNID" = "EPSS"."CVE"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "V"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS" AS "A"
                ON "COMPONENT"."ID" = "A"."COMPONENT_ID"
               AND "V"."ID" = "A"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "A"."PROJECT_ID"
             INNER JOIN "PROJECT"
                ON "COMPONENT"."PROJECT_ID" = "PROJECT"."ID"
             WHERE ${apiProjectAclCondition}
             <#if !activeFilter>
                AND "PROJECT"."INACTIVE_SINCE" IS NULL
             </#if>
             <#if !suppressedFilter>
                AND "A"."SUPPRESSED" IS DISTINCT FROM TRUE
             </#if>
             <#if queryFilter??>
                ${queryFilter}
             </#if>
             <#if apiOrderByClause??>
              ${apiOrderByClause}
             </#if>
             ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = "attribution.id", by = {
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "\"V\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "\"V\".\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"vulnSeverity\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"cvssV3BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"cvssV2BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "\"V\".\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "component.projectName", queryName = "concat(\"PROJECT\".\"NAME\", ' ', \"PROJECT\".\"VERSION\")"),
            @AllowApiOrdering.Column(name = "component.name", queryName = "\"COMPONENT\".\"NAME\""),
            @AllowApiOrdering.Column(name = "component.version", queryName = "\"COMPONENT\".\"VERSION\""),
            @AllowApiOrdering.Column(name = "analysis.state", queryName = "\"A\".\"STATE\""),
            @AllowApiOrdering.Column(name = "analysis.isSuppressed", queryName = "\"A\".\"SUPPRESSED\""),
            @AllowApiOrdering.Column(name = "attribution.id", queryName = "\"FINDINGATTRIBUTION\".\"ID\""),
            @AllowApiOrdering.Column(name = "attribution.attributedOn", queryName = "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"")
    })
    @DefineNamedBindings
    @AllowUnusedBindings
    @RegisterConstructorMapper(FindingRow.class)
    List<FindingRow> getAllFindings(@Define String queryFilter,
                                    @Define boolean activeFilter,
                                    @Define boolean suppressedFilter,
                                    @BindMap Map<String, Object> params);

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters.
     * @param filters        determines the filters to apply on the list of Finding objects
     * @param showSuppressed determines if suppressed vulnerabilities should be included or not
     * @param showInactive   determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    default List<FindingRow> getAllFindings(final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        processFilters(filters, queryFilter, params);
        return getAllFindings(String.valueOf(queryFilter), showInactive, showSuppressed, params);
    }

    @SqlQuery("""
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            SELECT "VULNERABILITY"."SOURCE" AS "vulnSource"
                , "VULNERABILITY"."VULNID"
                , "VULNERABILITY"."TITLE" AS "vulnTitle"
                , COALESCE("ANALYSIS"."SEVERITY", "VULNERABILITY"."SEVERITY") AS "vulnSeverity"
                , CASE
                    WHEN "ANALYSIS"."SEVERITY" IS NOT NULL THEN "ANALYSIS"."CVSSV2SCORE"
                    ELSE "VULNERABILITY"."CVSSV2BASESCORE"
                  END                              AS "cvssV2BaseScore"
                , CASE
                    WHEN "ANALYSIS"."SEVERITY" IS NOT NULL THEN "ANALYSIS"."CVSSV3SCORE"
                    ELSE "VULNERABILITY"."CVSSV3BASESCORE"
                  END                              AS "cvssV3BaseScore"
                , "VULNERABILITY"."PUBLISHED" AS "vulnPublished"
                , CAST(STRING_TO_ARRAY("VULNERABILITY"."CWES", ',') AS INT[]) AS "CWES"
                , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                , COUNT(DISTINCT "PROJECT"."ID") AS "affectedProjectCount"
                , COUNT(*) OVER() AS "totalCount"
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
               , "vulnSeverity"
               , "cvssV2BaseScore"
               , "cvssV3BaseScore"
               , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
               , "VULNERABILITY"."PUBLISHED"
               , "VULNERABILITY"."CWES"
            <#if aggregateFilter??>
                ${aggregateFilter}
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = "vulnerability.id", by = {
            @AllowApiOrdering.Column(name = "vulnerability.id", queryName = "\"VULNERABILITY\".\"ID\""),
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "\"VULNERABILITY\".\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "\"VULNERABILITY\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"vulnSeverity\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"cvssV3BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"cvssV2BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "\"VULNERABILITY\".\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "vulnerability.affectedProjectCount", queryName = "COUNT(DISTINCT \"PROJECT\".\"ID\")")
    })
    @AllowUnusedBindings
    @DefineNamedBindings
    @RegisterConstructorMapper(GroupedFindingRow.class)
    List<GroupedFindingRow> getGroupedFindings(@Define String queryFilter,
                                               @Define boolean activeFilter,
                                               @Define String aggregateFilter,
                                               @BindMap Map<String, Object> params);

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters. The resulting list is grouped by vulnerability.
     *
     * @param filters       determines the filters to apply on the list of Finding objects
     * @param showInactive  determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    default List<GroupedFindingRow> getGroupedFindings(final Map<String, String> filters, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        processFilters(filters, queryFilter, params);
        StringBuilder aggregateFilter = new StringBuilder();
        processAggregateFilters(filters, aggregateFilter, params);
        return getGroupedFindings(String.valueOf(queryFilter), showInactive, String.valueOf(aggregateFilter), params);
    }

    private void processFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params) {
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

    private void processAggregateFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "occurrencesFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT \"PROJECT\".\"ID\")", true, false, true);
                case "occurrencesTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT \"PROJECT\".\"ID\")", false, false, true);
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
            if (queryFilter.isEmpty()) {
                queryFilter.append(isAggregateFilter ? " HAVING (" : " AND (");
            } else {
                queryFilter.append(" AND (");
            }
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