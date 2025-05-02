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
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.dependencytrack.metrics.Metrics.dropOldPartitions;

/**
 * @since 5.6.0
 */
public interface MetricsDao {

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
    List<ProjectMetrics> getProjectMetricsSince(@Bind Long projectId, @Bind Instant since);

    @SqlQuery("""
            SELECT * FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            AND "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    List<DependencyMetrics> getDependencyMetricsSince(@Bind Long componentId,@Bind Instant since);

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS "inheritedRiskScore"
            FROM "PORTFOLIOMETRICS"
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(PortfolioMetrics.class)
    PortfolioMetrics getMostRecentPortfolioMetrics();

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS "inheritedRiskScore"
            FROM "PROJECTMETRICS"
            WHERE "PROJECT_ID" = :projectId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    ProjectMetrics getMostRecentProjectMetrics(@Bind final long projectId);

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS "inheritedRiskScore"
            FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    DependencyMetrics getMostRecentDependencyMetrics(@Bind final long componentId);

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
                today DATE := current_date;
                tomorrow DATE := current_date + INTERVAL '1 day';
                partition_suffix TEXT := to_char(today, 'YYYYMMDD');
                partition_name TEXT;
            BEGIN
                -- PORTFOLIOMETRICS
                partition_name := format('PORTFOLIOMETRICS_%s', partition_suffix);
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF "PORTFOLIOMETRICS"
                     FOR VALUES FROM (%L) TO (%L);',
                    partition_name,
                    today,
                    tomorrow
                );
            
                -- PROJECTMETRICS
                partition_name := format('PROJECTMETRICS_%s', partition_suffix);
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF "PROJECTMETRICS"
                     FOR VALUES FROM (%L) TO (%L);',
                    partition_name,
                    today,
                    tomorrow
                );
            
                -- DEPENDENCYMETRICS
                partition_name := format('DEPENDENCYMETRICS_%s', partition_suffix);
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF "DEPENDENCYMETRICS"
                     FOR VALUES FROM (%L) TO (%L);',
                    partition_name,
                    today,
                    tomorrow
                );
            END;
            $$;
            """)
    void createMetricsPartitionsForToday();

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
}
