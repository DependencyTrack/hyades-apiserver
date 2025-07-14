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

import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.pagination.Page;
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

import static org.dependencytrack.persistence.pagination.PageUtil.decodePageToken;
import static org.dependencytrack.persistence.pagination.PageUtil.encodePageToken;

/**
 * @since 5.6.0
 */
public interface MetricsDao extends SqlObject {

    record ListVulnerabilityMetricsPageToken(int year, int month) {
    }

    record ListVulnerabilityMetricsRow(int year, int month, int count, Instant measuredAt) {
    }

    default Page<ListVulnerabilityMetricsRow> getVulnerabilityMetrics(final int limit, final String pageToken) {
        final var decodedPageToken = decodePageToken(getHandle(), pageToken, ListVulnerabilityMetricsPageToken.class);

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

        return new Page<>(resultRows, encodePageToken(getHandle(), nextPageToken));
    }

    @SqlQuery("""
            SELECT * FROM "PORTFOLIOMETRICS"
            WHERE "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(PortfolioMetrics.class)
    List<PortfolioMetrics> getPortfolioMetricsSince(@Bind Instant since);

    @SqlQuery("""
            SELECT * FROM "PROJECTMETRICS"
            WHERE "PROJECT_ID" = :projectId
            AND "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    List<ProjectMetrics> getProjectMetricsSince(@Bind long projectId, @Bind Instant since);

    @SqlQuery("""
            SELECT * FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            AND "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    List<DependencyMetrics> getDependencyMetricsSince(@Bind long componentId, @Bind Instant since);

    @SqlQuery("""
            SELECT *
            FROM "PORTFOLIOMETRICS"
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(PortfolioMetrics.class)
    PortfolioMetrics getMostRecentPortfolioMetrics();

    @SqlQuery("""
            SELECT *
            FROM "PROJECTMETRICS"
            WHERE "PROJECT_ID" = :projectId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    ProjectMetrics getMostRecentProjectMetrics(@Bind final long projectId);

    @SqlQuery("""
            SELECT metrics.*
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
            SELECT *
            FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    DependencyMetrics getMostRecentDependencyMetrics(@Bind long componentId);

    @SqlQuery("""
            SELECT metrics.*
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
            WHERE inhparent = '"PORTFOLIOMETRICS"'::regclass;
            """)
    List<String> getPortfolioMetricsPartitions();

    @SqlQuery("""
            SELECT inhrelid::regclass AS partition_name
            FROM pg_inherits
            WHERE inhparent = '"PROJECTMETRICS"'::regclass;
            """)
    List<String> getProjectMetricsPartitions();

    @SqlQuery("""
            SELECT inhrelid::regclass AS partition_name
            FROM pg_inherits
            WHERE inhparent = '"DEPENDENCYMETRICS"'::regclass;
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
                metric_tables TEXT[] := ARRAY['PORTFOLIOMETRICS', 'PROJECTMETRICS', 'DEPENDENCYMETRICS'];
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

    default int deletePortfolioMetricsForRetentionDuration(Duration retentionDuration) {
        List<String> metricsPartitions = getPortfolioMetricsPartitions();
        return dropOldPartitions(metricsPartitions, retentionDuration);
    }

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
