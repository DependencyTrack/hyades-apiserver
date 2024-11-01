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
package org.dependencytrack.job.persistence;

import org.dependencytrack.job.JobStatus;
import org.dependencytrack.job.QueuedJob;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;

final class QueuedJobRowMapper implements RowMapper<QueuedJob> {

    @Override
    public QueuedJob map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new QueuedJob(
                rs.getLong("ID"),
                JobStatus.valueOf(rs.getString("STATUS")),
                rs.getString("KIND"),
                nullableInteger(rs, "PRIORITY"),
                Instant.ofEpochMilli(rs.getTimestamp("SCHEDULED_FOR").getTime()),
                null,
                null,
                rs.getLong("WORKFLOW_STEP_RUN_ID"),
                Instant.ofEpochMilli(rs.getDate("CREATED_AT").getTime()),
                nullableInstant(rs, "UPDATED_AT"),
                nullableInstant(rs, "STARTED_AT"),
                rs.getInt("ATTEMPTS"),
                rs.getString("FAILURE_REASON")
        );
    }

    private static Instant nullableInstant(final ResultSet rs, final String columnName) throws SQLException {
        final Timestamp date = rs.getTimestamp(columnName);
        if (rs.wasNull()) {
            return null;
        }

        return Instant.ofEpochMilli(date.getTime());
    }

    private static Integer nullableInteger(final ResultSet rs, final String columnName) throws SQLException {
        final int integer = rs.getInt(columnName);
        if (rs.wasNull()) {
            return null;
        }

        return integer;
    }

}
