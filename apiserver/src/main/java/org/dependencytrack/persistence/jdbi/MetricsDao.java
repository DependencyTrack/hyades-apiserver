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

/**
 * @since 5.6.0
 */
public interface MetricsDao {

    @SqlUpdate("""
            DELETE
              FROM "DEPENDENCYMETRICS"
             USING "PROJECT"
             WHERE "PROJECT"."ID" = "DEPENDENCYMETRICS"."PROJECT_ID"
               AND "PROJECT"."INACTIVE_SINCE" IS NULL
               AND "DEPENDENCYMETRICS"."LAST_OCCURRENCE" < (NOW() - :duration)
            """)
    int deleteComponentMetricsForRetentionDuration(@Bind Duration duration);

    @SqlUpdate("""
            DELETE
              FROM "PROJECTMETRICS"
             USING "PROJECT"
             WHERE "PROJECT"."ID" = "PROJECTMETRICS"."PROJECT_ID"
               AND "PROJECT"."INACTIVE_SINCE" IS NULL
               AND "PROJECTMETRICS"."LAST_OCCURRENCE" < (NOW() - :duration)
            """)
    int deleteProjectMetricsForRetentionDuration(@Bind Duration duration);

    @SqlUpdate("""
            DELETE
              FROM "PORTFOLIOMETRICS"
             WHERE "LAST_OCCURRENCE" < (NOW() - :duration)
            """)
    int deletePortfolioMetricsForRetentionDuration(@Bind Duration duration);

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
}
