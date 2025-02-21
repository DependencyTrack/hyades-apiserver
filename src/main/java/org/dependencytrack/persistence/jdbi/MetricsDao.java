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
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * @since 5.6.0
 */
public interface MetricsDao extends SqlObject {

    // TODO:
    //   * Cache result for a few min in an unlogged table?
    default List<PortfolioMetrics> getPortfolioMetricsSince(@Bind Instant since) {
        final Query query = getHandle().createQuery("""
                WITH
                cte_latest_project_metrics AS(
                  SELECT "PROJECTMETRICS"."ID" AS id
                       , DATE("LAST_OCCURRENCE") AS occurrence_date
                       , ROW_NUMBER() OVER(PARTITION BY "PROJECT_ID", DATE("LAST_OCCURRENCE") ORDER BY "LAST_OCCURRENCE" DESC) AS rn
                    FROM "PROJECTMETRICS"
                   INNER JOIN "PROJECT"
                      ON "PROJECT"."ID" = "PROJECTMETRICS"."PROJECT_ID"
                   WHERE "LAST_OCCURRENCE" >= :since
                     AND "PROJECT"."INACTIVE_SINCE" IS NULL
                     AND ${apiProjectAclCondition!"TRUE"}
                ),
                cte_dates AS(
                  SELECT CAST(t.the_day AS DATE) AS day
                    FROM GENERATE_SERIES(:since, NOW(), '1 day') AS t(the_day)
                )
                SELECT SUM(CASE WHEN metrics."ID" > 0 THEN 1 ELSE 0 END) as projects
                     , COALESCE(SUM(CASE WHEN metrics."VULNERABILITIES" > 0 THEN 1 ELSE 0 END), 0) AS vulnerable_projects
                     , COALESCE(SUM(metrics."COMPONENTS"), 0) AS components
                     , COALESCE(SUM(metrics."VULNERABLECOMPONENTS"), 0) AS vulnerable_components
                     , COALESCE(SUM(metrics."VULNERABILITIES"), 0) as vulnerabilities
                     , COALESCE(SUM(metrics."CRITICAL"), 0) AS critical
                     , COALESCE(SUM(metrics."HIGH"), 0) AS high
                     , COALESCE(SUM(metrics."MEDIUM"), 0) AS medium
                     , COALESCE(SUM(metrics."LOW"), 0) AS low
                     , COALESCE(SUM(metrics."UNASSIGNED_SEVERITY"), 0) AS unassigned
                     , "CALC_RISK_SCORE"(
                         CAST(COALESCE(SUM(metrics."CRITICAL"), 0) AS INT)
                       , CAST(COALESCE(SUM(metrics."HIGH"), 0) AS INT)
                       , CAST(COALESCE(SUM(metrics."MEDIUM"), 0) AS INT)
                       , CAST(COALESCE(SUM(metrics."LOW"), 0) AS INT)
                       , CAST(COALESCE(SUM(metrics."UNASSIGNED_SEVERITY"), 0) AS INT)
                       ) AS inherited_risk_core
                     , COALESCE(SUM(metrics."FINDINGS_TOTAL"), 0) AS findings_total
                     , COALESCE(SUM(metrics."FINDINGS_AUDITED"), 0) AS findings_audited
                     , COALESCE(SUM(metrics."FINDINGS_UNAUDITED"), 0) AS findings_unaudited
                     , COALESCE(SUM(metrics."SUPPRESSED"), 0) AS suppressed
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_TOTAL"), 0) AS policy_violations_total
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_FAIL"), 0) AS policy_violations_fail
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_WARN"), 0) AS policy_violations_warn
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_INFO"), 0) AS policy_violations_info
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_AUDITED"), 0) AS policy_violations_audited
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_UNAUDITED"), 0) AS policy_violations_unaudited
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_LICENSE_TOTAL"), 0) AS policy_violations_license_total
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_LICENSE_AUDITED"), 0) AS policy_violations_license_audited
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_LICENSE_UNAUDITED"), 0) AS policy_violations_license_unaudited
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_OPERATIONAL_TOTAL"), 0) AS policy_violations_operational_total
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_OPERATIONAL_AUDITED"), 0) AS policy_violations_operational_audited
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"), 0) AS policy_violations_operational_unaudited
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_SECURITY_TOTAL"), 0) AS policy_violations_security_total
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_SECURITY_AUDITED"), 0) AS policy_violations_security_audited
                     , COALESCE(SUM(metrics."POLICYVIOLATIONS_SECURITY_UNAUDITED"), 0) AS policy_violations_security_unaudited
                     , CAST(cte_dates.day AS TIMESTAMPTZ) AS first_occurrence
                     , CAST(cte_dates.day AS TIMESTAMPTZ) AS last_occurrence
                  FROM cte_dates
                  LEFT JOIN cte_latest_project_metrics
                    ON cte_latest_project_metrics.occurrence_date = cte_dates.day
                   AND cte_latest_project_metrics.rn = 1
                  LEFT JOIN "PROJECTMETRICS" AS metrics
                    ON metrics."ID" = cte_latest_project_metrics.id
                GROUP BY day
                ORDER BY day
                """);

        return query
                .bind("since", since)
                .map(BeanMapper.of(PortfolioMetrics.class))
                .list();
    }

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
