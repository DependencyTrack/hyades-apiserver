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

import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Duration;

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

}
