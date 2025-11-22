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

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.List;

/**
 * @since 5.6.0
 */
public interface MetricsDao extends SqlObject {

    record ListVulnerabilityMetricsPageToken(int year, int month) implements PageToken {
    }

    record ListVulnerabilityMetricsRow(int year, int month, int count, Instant measuredAt) {
    }

    default Page<ListVulnerabilityMetricsRow> getVulnerabilityMetrics(final int limit, final String pageToken) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListVulnerabilityMetricsPageToken.class);

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="year" type="Boolean" -->
                <#-- @ftlvariable name="month" type="Boolean" -->
                SELECT *
                FROM "VULNERABILITYMETRICS"
                WHERE TRUE
                <#if year && month>
                    AND ("YEAR", "MONTH") > (:year, :month)
                </#if>
                ORDER BY "YEAR" ASC, "MONTH" ASC
                LIMIT :limit
            """);

        final List<ListVulnerabilityMetricsRow> rows = query
                .bind("year", decodedPageToken != null
                        ? decodedPageToken.year()
                        : null)
                .bind("month", decodedPageToken != null
                        ? decodedPageToken.month()
                        : null)
                .bind("limit", limit + 1)
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListVulnerabilityMetricsRow.class))
                .list();

        final List<ListVulnerabilityMetricsRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListVulnerabilityMetricsPageToken nextPageToken = rows.size() > limit
                ? new ListVulnerabilityMetricsPageToken(resultRows.getLast().year, resultRows.getLast().month)
                : null;

        return new Page<>(resultRows, pageTokenEncoder.encode(nextPageToken));
    }

    /**
     * Compute the portfolio metrics for the projects accessible by the calling principal.
     * <p>
     * If portfolio ACL is disabled, or the principal is bypassing ACL in any other
     * way, the query selects from the {@code PORTFOLIOMETRICS_GLOBAL} materialized view
     * rather than performing ad-hoc aggregations. The assumption is that most users
     * will only have access to a small subset of projects, even if the entire portfolio
     * span multiple 10s of thousands of projects. But users who bypass ACL restrictions
     * would need aggregations to be performed over a large set of projects, which is
     * not feasible.
     * <p>
     * Note that <code>generate_series</code> is invoked with integers rather
     * than <code>date</code>s, because the query planner tends to overestimate
     * rows with the latter approach.
     *
     * @see <a href="https://stackoverflow.com/a/66279403">generate_series quirk</a>
     */
    @SqlQuery("""
            <#if apiProjectAclCondition?c_lower_case == 'true'>
            SELECT *
              FROM "PORTFOLIOMETRICS_GLOBAL"
             WHERE "LAST_OCCURRENCE" >= CURRENT_DATE - (INTERVAL '1 day' * (:days - 1))
             ORDER BY "LAST_OCCURRENCE";
            <#else>
            WITH
            date_range AS(
              SELECT DATE_TRUNC('day', CURRENT_DATE - (INTERVAL '1 day' * day)) AS metrics_date
                FROM GENERATE_SERIES(0, GREATEST(:days - 1, 0)) day
            ),
            projects_in_scope AS(
              SELECT "ID"
                FROM "PROJECT"
               WHERE "INACTIVE_SINCE" IS NULL
                 AND ${apiProjectAclCondition}
            ),
            latest_daily_project_metrics AS(
              SELECT date_range.metrics_date
                   , latest_metrics.*
               FROM date_range
               LEFT JOIN LATERAL (
                 SELECT DISTINCT ON (pm."PROJECT_ID")
                        pm.*
                   FROM projects_in_scope
                  INNER JOIN "PROJECTMETRICS" pm
                     ON pm."PROJECT_ID" = projects_in_scope."ID"
                  WHERE pm."LAST_OCCURRENCE" < date_range.metrics_date + INTERVAL '1 day'
                    -- Consider data from previous day in case we don't have any for today.
                    AND pm."LAST_OCCURRENCE" >= date_range.metrics_date - INTERVAL '1 day'
                  ORDER BY pm."PROJECT_ID", pm."LAST_OCCURRENCE" DESC
               ) AS latest_metrics ON TRUE
            ),
            daily_metrics AS(
              SELECT COUNT(DISTINCT "PROJECT_ID") AS projects
                   , SUM("COMPONENTS") AS components
                   , SUM("CRITICAL") AS critical
                   , metrics_date
                   , SUM("FINDINGS_AUDITED") AS findings_audited
                   , SUM("FINDINGS_TOTAL") AS findings_total
                   , SUM("FINDINGS_UNAUDITED") AS findings_unaudited
                   , SUM("HIGH") AS high
                   , SUM("RISKSCORE") as inherited_risk_score
                   , SUM("LOW") AS low
                   , SUM("MEDIUM") AS medium
                   , SUM("POLICYVIOLATIONS_AUDITED") AS policy_violations_audited
                   , SUM("POLICYVIOLATIONS_FAIL") AS policy_violations_fail
                   , SUM("POLICYVIOLATIONS_INFO") AS policy_violations_info
                   , SUM("POLICYVIOLATIONS_LICENSE_AUDITED") AS policy_violations_license_audited
                   , SUM("POLICYVIOLATIONS_LICENSE_TOTAL") AS policy_violations_license_total
                   , SUM("POLICYVIOLATIONS_LICENSE_UNAUDITED") AS policy_violations_license_unaudited
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_AUDITED") AS policy_violations_operational_audited
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_TOTAL") AS policy_violations_operational_total
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_UNAUDITED") AS policy_violations_operational_unaudited
                   , SUM("POLICYVIOLATIONS_SECURITY_AUDITED") AS policy_violations_security_audited
                   , SUM("POLICYVIOLATIONS_SECURITY_TOTAL") AS policy_violations_security_total
                   , SUM("POLICYVIOLATIONS_SECURITY_UNAUDITED") AS policy_violations_security_unaudited
                   , SUM("POLICYVIOLATIONS_TOTAL") AS policy_violations_total
                   , SUM("POLICYVIOLATIONS_UNAUDITED") AS policy_violations_unaudited
                   , SUM("POLICYVIOLATIONS_WARN") AS policy_violations_warn
                   , SUM("SUPPRESSED") AS suppressed
                   , SUM("UNASSIGNED_SEVERITY") AS unassigned
                   , SUM("VULNERABILITIES") AS vulnerabilities
                   , SUM("VULNERABLECOMPONENTS") AS vulnerable_components
                   , SUM(CASE WHEN "VULNERABLECOMPONENTS" > 0 THEN 1 ELSE 0 END) AS vulnerable_projects
                FROM latest_daily_project_metrics
               GROUP BY metrics_date
            )
            SELECT COALESCE(dm.components, 0) AS components
                 , COALESCE(dm.critical, 0) AS critical
                 , COALESCE(dm.findings_audited, 0) AS findings_audited
                 , COALESCE(dm.findings_total, 0) AS findings_total
                 , COALESCE(dm.findings_unaudited, 0) AS findings_unaudited
                 , date_range.metrics_date AS first_occurrence
                 , COALESCE(dm.high, 0) AS high
                 , COALESCE(dm.inherited_risk_score, 0) AS inherited_risk_score
                 , date_range.metrics_date AS last_occurrence
                 , COALESCE(dm.low, 0) AS low
                 , COALESCE(dm.medium, 0) AS medium
                 , COALESCE(dm.policy_violations_audited, 0) AS policy_violations_audited
                 , COALESCE(dm.policy_violations_fail, 0) AS policy_violations_fail
                 , COALESCE(dm.policy_violations_info, 0) AS policy_violations_info
                 , COALESCE(dm.policy_violations_license_audited, 0) AS policy_violations_license_audited
                 , COALESCE(dm.policy_violations_license_total, 0) AS policy_violations_license_total
                 , COALESCE(dm.policy_violations_license_unaudited, 0) AS policy_violations_license_unaudited
                 , COALESCE(dm.policy_violations_operational_audited, 0) AS policy_violations_operational_audited
                 , COALESCE(dm.policy_violations_operational_total, 0) AS policy_violations_operational_total
                 , COALESCE(dm.policy_violations_operational_unaudited, 0) AS policy_violations_operational_unaudited
                 , COALESCE(dm.policy_violations_security_audited, 0) AS policy_violations_security_audited
                 , COALESCE(dm.policy_violations_security_total, 0) AS policy_violations_security_total
                 , COALESCE(dm.policy_violations_security_unaudited, 0) AS policy_violations_security_unaudited
                 , COALESCE(dm.policy_violations_total, 0) AS policy_violations_total
                 , COALESCE(dm.policy_violations_unaudited, 0) AS policy_violations_unaudited
                 , COALESCE(dm.policy_violations_warn, 0) AS policy_violations_warn
                 , COALESCE(dm.projects, 0) AS projects
                 , COALESCE(dm.suppressed, 0) AS suppressed
                 , COALESCE(dm.unassigned, 0) AS unassigned
                 , COALESCE(dm.vulnerabilities, 0) AS vulnerabilities
                 , COALESCE(dm.vulnerable_components, 0) AS vulnerable_components
                 , COALESCE(dm.vulnerable_projects, 0) AS vulnerable_projects
              FROM date_range
              LEFT JOIN daily_metrics AS dm
                ON date_range.metrics_date = dm.metrics_date
             ORDER BY date_range.metrics_date;
            </#if>
            """)
    @RegisterBeanMapper(PortfolioMetrics.class)
    List<PortfolioMetrics> getPortfolioMetricsForDays(@Bind int days);

    @SqlUpdate("""
            REFRESH MATERIALIZED VIEW CONCURRENTLY "PORTFOLIOMETRICS_GLOBAL"
            """)
    void refreshGlobalPortfolioMetrics();

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score FROM "PROJECTMETRICS"
            WHERE "PROJECT_ID" = :projectId
            AND "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    List<ProjectMetrics> getProjectMetricsSince(@Bind long projectId, @Bind Instant since);

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            AND "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    List<DependencyMetrics> getDependencyMetricsSince(@Bind long componentId, @Bind Instant since);

    default PortfolioMetrics getMostRecentPortfolioMetrics() {
        // Request metrics since yesterday, such that we cater for projects that do
        // not have fresh metrics from today yet.
        return getPortfolioMetricsForDays(2).getLast();
    }

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score
            FROM "PROJECTMETRICS"
            WHERE "PROJECT_ID" = :projectId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    ProjectMetrics getMostRecentProjectMetrics(@Bind final long projectId);

    @SqlQuery("""
            SELECT metrics.*, metrics."RISKSCORE" AS inherited_risk_score
              FROM UNNEST(:projectIds) AS project(id)
             INNER JOIN LATERAL (
               SELECT *
                 FROM "PROJECTMETRICS"
                WHERE "PROJECT_ID" = project.id
                ORDER BY "LAST_OCCURRENCE" DESC
                LIMIT 1
             ) AS metrics ON TRUE
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    List<ProjectMetrics> getMostRecentProjectMetrics(@Bind Collection<Long> projectIds);

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score
            FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    DependencyMetrics getMostRecentDependencyMetrics(@Bind long componentId);

    @SqlQuery("""
            SELECT metrics.*, metrics."RISKSCORE" AS inherited_risk_score
              FROM UNNEST(:componentIds) AS component(id)
             INNER JOIN LATERAL (
               SELECT *
                 FROM "DEPENDENCYMETRICS"
                WHERE "COMPONENT_ID" = component.id
                ORDER BY "LAST_OCCURRENCE" DESC
                LIMIT 1
             ) AS metrics ON TRUE
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    List<DependencyMetrics> getMostRecentDependencyMetrics(@Bind Collection<Long> componentIds);

    @SqlQuery("""
            SELECT inhrelid::regclass AS partition_name
            FROM pg_inherits
            WHERE inhparent = '"PROJECTMETRICS"'::regclass
            ORDER BY partition_name;
            """)
    List<String> getProjectMetricsPartitions();

    @SqlQuery("""
            SELECT inhrelid::regclass AS partition_name
            FROM pg_inherits
            WHERE inhparent = '"DEPENDENCYMETRICS"'::regclass
            ORDER BY partition_name;
            """)
    List<String> getDependencyMetricsPartitions();

    @SqlUpdate("""
            DO $$
            DECLARE
                today DATE := DATE '${targetDate}';
                tomorrow DATE := DATE '${nextDate}';
                partition_suffix TEXT := to_char(today, 'YYYYMMDD');
                partition_name TEXT;
                partition_exists BOOLEAN;
                table_name TEXT;
                metric_tables TEXT[] := ARRAY['PROJECTMETRICS', 'DEPENDENCYMETRICS'];
            BEGIN
                FOREACH table_name IN ARRAY metric_tables
                LOOP
                    partition_name := format('%s_%s', table_name, partition_suffix);
                    SELECT EXISTS (
                        SELECT 1 FROM pg_class WHERE relname = partition_name
                    ) INTO partition_exists;
            
                    IF NOT partition_exists THEN
                        EXECUTE format(
                            'CREATE TABLE IF NOT EXISTS %I (LIKE %I INCLUDING ALL);',
                            partition_name,
                            table_name
                        );
                        EXECUTE format(
                            'ALTER TABLE %I ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L);',
                            table_name,
                            partition_name,
                            today,
                            tomorrow
                        );
                    END IF;
                END LOOP;
            END;
            $$;
            """)
    void createMetricsPartitionsForDate(@Define("targetDate") String targetDate, @Define("nextDate") String nextDate);

    default int deleteProjectMetricsForRetentionDuration(Duration retentionDuration) {
        List<String> metricsPartitions = getProjectMetricsPartitions();
        return dropOldPartitions(metricsPartitions, retentionDuration);
    }

    default int deleteComponentMetricsForRetentionDuration(Duration retentionDuration) {
        List<String> metricsPartitions = getDependencyMetricsPartitions();
        return dropOldPartitions(metricsPartitions, retentionDuration);
    }

    default int dropOldPartitions(final List<String> metricsPartitions, final Duration retentionDuration) {
        LocalDate cutoffDate = LocalDate.now().minusDays(retentionDuration.toDays());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        int deletedCount = 0;
        for (String partition : metricsPartitions) {
            String[] parts = partition.replace("\"", "").split("_");
            LocalDate partitionDate = LocalDate.parse(parts[1], formatter);
            if (partitionDate.isBefore(cutoffDate) || partitionDate.isEqual(cutoffDate)) {
                String sql = String.format("DROP TABLE IF EXISTS %s CASCADE;", partition);
                getHandle().execute(sql);
                deletedCount++;
            }
        }
        return deletedCount;
    }
}
