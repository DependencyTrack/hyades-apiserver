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
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public interface MetricsTestDao extends SqlObject {


    @SqlQuery("""
            INSERT INTO "PORTFOLIOMETRICS"(
                "PROJECTS", "COMPONENTS", "FIRST_OCCURRENCE", "LAST_OCCURRENCE", "CRITICAL", "HIGH", "MEDIUM", "LOW", "RISKSCORE",
                "SUPPRESSED", "VULNERABILITIES", "VULNERABLEPROJECTS", "VULNERABLECOMPONENTS")
            VALUES (:projects, :components, :firstOccurrence, :lastOccurrence, :critical, :high, :medium, :low, :inheritedRiskScore,
                 :suppressed, :vulnerabilities, :vulnerableProjects, :vulnerableComponents)
            RETURNING *
            """)
    @RegisterBeanMapper(PortfolioMetrics.class)
    PortfolioMetrics createPortfolioMetrics(@BindBean PortfolioMetrics portfolioMetrics);


    @SqlQuery("""
            INSERT INTO "PROJECTMETRICS"(
                "PROJECT_ID", "COMPONENTS", "FIRST_OCCURRENCE", "LAST_OCCURRENCE", "CRITICAL", "HIGH", "MEDIUM", "LOW", "RISKSCORE",
                "SUPPRESSED", "VULNERABILITIES", "VULNERABLECOMPONENTS")
            VALUES (:projectId, :components, :firstOccurrence, :lastOccurrence, :critical, :high, :medium, :low, :inheritedRiskScore,
                 :suppressed, :vulnerabilities, :vulnerableComponents)
            RETURNING *
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    ProjectMetrics createProjectMetrics(@BindBean ProjectMetrics projectMetrics);

    @SqlQuery("""
            INSERT INTO "DEPENDENCYMETRICS"(
                "COMPONENT_ID", "PROJECT_ID", "FIRST_OCCURRENCE", "LAST_OCCURRENCE", "CRITICAL", "HIGH", "MEDIUM", "LOW", "RISKSCORE",
                "SUPPRESSED", "VULNERABILITIES")
            VALUES (:componentId, :projectId, :firstOccurrence, :lastOccurrence, :critical, :high, :medium, :low, :inheritedRiskScore,
                 :suppressed, :vulnerabilities)
            RETURNING *
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    DependencyMetrics createDependencyMetrics(@BindBean DependencyMetrics dependencyMetrics);

    default void createMetricsPartitionsForDate(String tableName, LocalDate targetDate) {
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
        getHandle().execute(sql);
    }

    default void createPartitionForDaysAgo(String tableName, int daysAgo) {
        LocalDate targetDate = LocalDate.now().minusDays(daysAgo);
        createMetricsPartitionsForDate(tableName, targetDate);
    }
}
