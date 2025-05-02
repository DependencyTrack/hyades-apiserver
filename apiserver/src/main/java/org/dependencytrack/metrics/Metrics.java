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
package org.dependencytrack.metrics;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Helper class for enhancing metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class Metrics {

    static final Logger LOGGER = LoggerFactory.getLogger(Metrics.class);

    private Metrics() {
    }

    public static double inheritedRiskScore(final int critical, final int high, final int medium, final int low, final int unassigned) {
        return (double) ((critical * 10) + (high * 5) + (medium * 3) + (low * 1) + (unassigned * 5));
    }

    public static double vulnerableComponentRatio(final int vulnerabilities, final int vulnerableComponents) {
        double ratio = 0.0;
        if (vulnerableComponents > 0) {
            ratio = (double) vulnerabilities / vulnerableComponents;
        }
        return ratio;
    }

    /**
     * Update metrics for the entire portfolio.
     * <p>
     * Note: This does not implicitly update metrics for all projects in the portfolio,
     * it merely aggregates all existing {@link ProjectMetrics}.
     *
     * @since 5.0.0
     */
    public static void updatePortfolioMetrics() {
        useJdbiHandle(handle -> handle.createCall("CALL \"UPDATE_PORTFOLIO_METRICS\"()").invoke());
    }

    /**
     * Update metrics for a given {@link Project}.
     *
     * @param projectUuid {@link UUID} of the {@link Project} to update metrics for
     * @since 5.0.0
     */
    public static void updateProjectMetrics(final UUID projectUuid) {
        useJdbiHandle(handle -> handle
                .createCall("CALL \"UPDATE_PROJECT_METRICS\"(:uuid)")
                .bind("uuid", projectUuid)
                .invoke());
    }

    /**
     * Update metrics for a given {@link Component}.
     *
     * @param componentUuid {@link UUID} of the {@link Component} to update metrics for
     * @since 5.0.0
     */
    public static void updateComponentMetrics(final UUID componentUuid) {
        useJdbiHandle(handle -> handle
                .createCall("CALL \"UPDATE_COMPONENT_METRICS\"(:uuid)")
                .bind("uuid", componentUuid)
                .invoke());
    }

    public static int dropOldPartitions(final List<String> metricsPartitions, final Duration retentionDuration) {
        LocalDate cutoffDate = LocalDate.now().minusDays(retentionDuration.toDays());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        int deletedCount = 0;
        for (String partition : metricsPartitions) {
            String[] parts = partition.replace("\"", "").split("_");
            LocalDate partitionDate = LocalDate.parse(parts[1], formatter);
            if (partitionDate.isBefore(cutoffDate) || partitionDate.isEqual(cutoffDate)) {
                try {
                    String sql = String.format("DROP TABLE IF EXISTS %s CASCADE;", partition);
                    withJdbiHandle(handle -> handle.execute(sql));
                    deletedCount ++;
                } catch (Exception e) {
                    LOGGER.debug("Partition %s failed to be dropped.", partition, e);
                }
            }
        }
        return deletedCount;
    }

    public static void createPartitionForDaysAgo(String tableName, int daysAgo) {
        LocalDate targetDate = LocalDate.now().minusDays(daysAgo);
        createPartitionForDate(tableName, targetDate);
    }

    public static void createPartitionForDate(String tableName, LocalDate targetDate) {
        LocalDate nextDay = targetDate.plusDays(1);
        String partitionSuffix = targetDate.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String partitionName = tableName + "_" + partitionSuffix;
        String sql = String.format("""
            CREATE TABLE IF NOT EXISTS %s PARTITION OF %s
            FOR VALUES FROM ('%s') TO ('%s');
        """,
                "\"" + partitionName + "\"",
                "\"" + tableName + "\"",
                targetDate,
                nextDay
        );
        withJdbiHandle(handle -> handle.execute(sql));
    }
}
