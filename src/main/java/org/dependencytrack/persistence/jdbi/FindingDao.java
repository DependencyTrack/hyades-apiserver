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
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.RepositoryQueryManager.RepositoryMetaComponentSearch;
import org.dependencytrack.util.PurlUtil;
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
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

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
            boolean suppressed
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
            int affectedProjectCount
    ) {
    }

    @SqlQuery("""
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "PROJECT"."NAME" AS "projectName"
                 , "PROJECT"."VERSION" AS "projectVersion"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME" AS "componentName"
                 , "COMPONENT"."GROUP" AS "componentGroup"
                 , "COMPONENT"."VERSION" AS "componentVersion"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE" AS "componentCpe"
                 , "VULNERABILITY"."UUID" AS "vulnUuid"
                 , "VULNERABILITY"."SOURCE" AS "vulnSource"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE" AS "vulnTitle"
                 , "VULNERABILITY"."SUBTITLE" AS "vulnSubtitle"
                 , "VULNERABILITY"."DESCRIPTION" AS "vulnDescription"
                 , "VULNERABILITY"."RECOMMENDATION" AS "vulnRecommendation"
                 , "VULNERABILITY"."PUBLISHED" AS "vulnPublished"
                 , "VULNERABILITY"."SEVERITY" AS "vulnSeverity"
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
                 , "EPSS"."SCORE" AS "epssScore"
                 , "EPSS"."PERCENTILE" AS "epssPercentile"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE" AS "analysisState"
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
    @RegisterConstructorMapper(FindingRow.class)
    List<FindingRow> getFindingsByProject(@Bind long projectId, @Bind boolean includeSuppressed);

    default List<Finding> getFindings(final long projectId, final boolean includeSuppressed) {
        List<FindingRow> findingRows = withJdbiHandle(handle ->
                getFindingsByProject(projectId, includeSuppressed));
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
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "PROJECT"."NAME" AS "projectName"
                 , "PROJECT"."VERSION" AS "projectVersion"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME" AS "componentName"
                 , "COMPONENT"."GROUP" AS "componentGroup"
                 , "COMPONENT"."VERSION" AS "componentVersion"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE" AS "componentCpe"
                 , "VULNERABILITY"."UUID" AS "vulnUuid"
                 , "VULNERABILITY"."SOURCE" AS "vulnSource"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE" AS "vulnTitle"
                 , "VULNERABILITY"."SUBTITLE" AS "vulnSubtitle"
                 , "VULNERABILITY"."DESCRIPTION" AS "vulnDescription"
                 , "VULNERABILITY"."RECOMMENDATION" AS "vulnRecommendation"
                 , "VULNERABILITY"."PUBLISHED" AS "vulnPublished"
                 , "VULNERABILITY"."SEVERITY" AS "vulnSeverity"
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
                 , "EPSS"."SCORE" AS "epssScore"
                 , "EPSS"."PERCENTILE" AS "epssPercentile"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE" AS "analysisState"
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
             WHERE ${apiProjectAclCondition}
             <#if !activeFilter>
                AND "PROJECT"."INACTIVE_SINCE" IS NULL
             </#if>
             <#if !suppressedFilter>
                AND ("ANALYSIS"."SUPPRESSED" IS NULL OR NOT "ANALYSIS"."SUPPRESSED")
             </#if>
             <#if queryFilter??>
                ${queryFilter}
             </#if>
             <#if apiOrderByClause??>
              ${apiOrderByClause}
             </#if>
            """)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "\"VULNERABILITY\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "\"VULNERABILITY\".\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = """ 
                     CASE WHEN "VULNERABILITY"."SEVERITY" = 'UNASSIGNED' 
                          THEN 0 
                          WHEN "VULNERABILITY"."SEVERITY" = 'LOW' 
                          THEN 3 
                          WHEN "VULNERABILITY"."SEVERITY" = 'MEDIUM' 
                          THEN 6 
                          WHEN "VULNERABILITY"."SEVERITY" = 'HIGH' 
                          THEN 8 
                          WHEN "VULNERABILITY"."SEVERITY" = 'CRITICAL' 
                          THEN 10 
                          ELSE CASE WHEN "VULNERABILITY"."CVSSV3BASESCORE" IS NOT NULL 
                                    THEN "VULNERABILITY"."CVSSV3BASESCORE" 
                                    ELSE "VULNERABILITY"."CVSSV2BASESCORE" 
                               END 
                     END 
                     """),
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
    default PaginatedResult getAllFindings(final AlpineRequest alpineRequest, final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        processFilters(filters, queryFilter, params);
        final List<FindingRow> findingRows = withJdbiHandle(handle ->
                getAllFindings(String.valueOf(queryFilter), showInactive, showSuppressed, params));
        List<Finding> findings = findingRows.stream().map(Finding::new).toList();
        PaginatedResult result = new PaginatedResult();
        result.setTotal(findings.size());
        List<Finding> findingList = findings.subList(alpineRequest.getPagination().getOffset(),
                Math.min(alpineRequest.getPagination().getOffset() + alpineRequest.getPagination().getLimit(), findings.size()));
        findingList = mapComponentLatestVersion(findingList);
        result.setObjects(findingList);
        return result;
    }

    @SqlQuery("""
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            SELECT "VULNERABILITY"."SOURCE" AS "vulnSource"
                , "VULNERABILITY"."VULNID"
                , "VULNERABILITY"."TITLE" AS "vulnTitle"
                , "VULNERABILITY"."SEVERITY" AS "vulnSeverity"
                , "VULNERABILITY"."CVSSV2BASESCORE"
                , "VULNERABILITY"."CVSSV3BASESCORE"
                , "VULNERABILITY"."PUBLISHED" AS "vulnPublished"
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
               , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
               , "VULNERABILITY"."PUBLISHED"
               , "VULNERABILITY"."CWES"
            <#if aggregateFilter??>
                ${aggregateFilter}
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            </#if>
            """)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "\"VULNERABILITY\".\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "\"VULNERABILITY\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = """ 
                     CASE WHEN "VULNERABILITY"."SEVERITY" = 'UNASSIGNED' 
                          THEN 0 
                          WHEN "VULNERABILITY"."SEVERITY" = 'LOW' 
                          THEN 3 
                          WHEN "VULNERABILITY"."SEVERITY" = 'MEDIUM' 
                          THEN 6 
                          WHEN "VULNERABILITY"."SEVERITY" = 'HIGH' 
                          THEN 8 
                          WHEN "VULNERABILITY"."SEVERITY" = 'CRITICAL' 
                          THEN 10 
                          ELSE CASE WHEN "VULNERABILITY"."CVSSV3BASESCORE" IS NOT NULL 
                                    THEN "VULNERABILITY"."CVSSV3BASESCORE" 
                                    ELSE "VULNERABILITY"."CVSSV2BASESCORE" 
                               END 
                     END 
                     """),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"VULNERABILITY\".\"CVSSV3BASESCORE\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"VULNERABILITY\".\"CVSSV2BASESCORE\""),
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
    default PaginatedResult getGroupedFindings(final AlpineRequest alpineRequest, final Map<String, String> filters, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        processFilters(filters, queryFilter, params);
        StringBuilder aggregateFilter = new StringBuilder();
        processAggregateFilters(filters, aggregateFilter, params);
        final List<GroupedFindingRow> findingRows = withJdbiHandle(alpineRequest, handle ->
                getGroupedFindings(String.valueOf(queryFilter), showInactive, String.valueOf(aggregateFilter), params));
        List<GroupedFinding> findings = findingRows.stream().map(GroupedFinding::new).toList();
        PaginatedResult result = new PaginatedResult();
        result.setTotal(findings.size());
        final List<GroupedFinding> findingsList = findings.subList(alpineRequest.getPagination().getOffset(),
                Math.min(alpineRequest.getPagination().getOffset()
                        + alpineRequest.getPagination().getLimit(), findings.size()));
        result.setObjects(findingsList);
        return result;
    }

    private List<Finding> mapComponentLatestVersion(List<Finding> findingList){

        final Map<RepositoryMetaComponentSearch, List<Finding>> findingsByMetaComponentSearch = findingList.stream()
                .filter(finding -> finding.getComponent().get("purl") != null)
                .map(finding -> {
                    final PackageURL purl = PurlUtil.silentPurl((String) finding.getComponent().get("purl"));
                    if (purl == null) {
                        return null;
                    }

                    final var repositoryType = RepositoryType.resolve(purl);
                    if (repositoryType == RepositoryType.UNSUPPORTED) {
                        return null;
                    }

                    final var search = new RepositoryMetaComponentSearch(repositoryType, purl.getNamespace(), purl.getName());
                    return Map.entry(search, finding);
                })
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(
                        Map.Entry::getKey,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())
                ));

        final List<RepositoryMetaComponent> repositoryMetaComponents = withJdbiHandle(handle ->
                handle.attach(RepositoryMetaDao.class).getRepositoryMetaComponents(findingsByMetaComponentSearch.keySet()));
        repositoryMetaComponents.forEach(metaComponent -> {
            final var search = new RepositoryMetaComponentSearch(metaComponent.getRepositoryType(), metaComponent.getNamespace(), metaComponent.getName());
            final List<Finding> affectedFindings = findingsByMetaComponentSearch.get(search);
            if (affectedFindings != null) {
                for (final Finding finding : affectedFindings) {
                    finding.getComponent().put("latestVersion", metaComponent.getLatestVersion());
                }
            }
        });
        return findingList;
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