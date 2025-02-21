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

import org.dependencytrack.model.PortfolioMetrics;
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

    // TODO:
    //   * Get latest PROJECTMETRICS record for each project for each day.
    //   * Calculate metrics sums across all projects for each day.
    //   * Find a way to fill gaps (i.e. when no metrics exist for a project for a specific day)?
    //   * Cache result for a few min in an unlogged table?
    @SqlQuery("""
            with recursive
            directly_accessible_project as(
              select "PROJECT_ID" as id
                from "PROJECT_ACCESS_TEAMS"
               where "TEAM_ID" = any(:projectAclTeamIds)
            ),
            accessible_project_child(id) as(
              select "ID" as id
                from "PROJECT"
               where "PARENT_PROJECT_ID" IN (select id from directly_accessible_project)
               union all
              select "PROJECT"."ID" as id
                from "PROJECT"
               inner join accessible_project_child
                  on accessible_project_child.id = "PROJECT"."PARENT_PROJECT_ID"
            ),
            accessible_project as(
              select id
                from directly_accessible_project
               union all
              select id
                from accessible_project_child
            )
            select "PROJECTMETRICS".*
              from "PROJECT"
             inner join "PROJECTMETRICS"
                on "PROJECTMETRICS"."PROJECT_ID" = "PROJECT"."ID"
             where "PROJECT"."ID" in (select id from accessible_project)
               and "PROJECT"."INACTIVE_SINCE" IS NULL
               and "PROJECTMETRICS"."LAST_OCCURRENCE" >= :since;
            """)
    List<PortfolioMetrics> getPortfolioMetricsSince(@Bind Instant since);

    @SqlUpdate("""
            DELETE
              FROM "DEPENDENCYMETRICS"
             USING "PROJECT"
             WHERE "PROJECT"."ID" = "DEPENDENCYMETRICS"."PROJECT_ID"
               AND "PROJECT"."INACTIVE_SINCE" IS NULL
               AND NOW() - "DEPENDENCYMETRICS"."LAST_OCCURRENCE" > :duration
            """)
    int deleteComponentMetricsForRetentionDuration(@Bind Duration duration);

    @SqlUpdate("""
            DELETE
              FROM "PROJECTMETRICS"
             USING "PROJECT"
             WHERE "PROJECT"."ID" = "PROJECTMETRICS"."PROJECT_ID"
               AND "PROJECT"."INACTIVE_SINCE" IS NULL
               AND NOW() - "PROJECTMETRICS"."LAST_OCCURRENCE" > :duration
            """)
    int deleteProjectMetricsForRetentionDuration(@Bind Duration duration);

    @SqlUpdate("""
            DELETE
              FROM "PORTFOLIOMETRICS"
             WHERE NOW() - "LAST_OCCURRENCE" > :duration
            """)
    int deletePortfolioMetricsForRetentionDuration(@Bind Duration duration);

}
