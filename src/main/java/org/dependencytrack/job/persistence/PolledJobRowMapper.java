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
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.nullableInteger;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.nullableUuid;

public class PolledJobRowMapper implements RowMapper<PolledJob> {

    @Override
    public PolledJob map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new PolledJob(
                rs.getLong("ID"),
                JobStatus.valueOf(rs.getString("STATUS")),
                rs.getString("KIND"),
                nullableInteger(rs, "PRIORITY"),
                Instant.ofEpochMilli(rs.getTimestamp("SCHEDULED_FOR").getTime()),
                rs.getString("ARGUMENTS"),
                nullableUuid(rs, "WORKFLOW_RUN_ID"),
                rs.getString("WORKFLOW_ACTIVITY_NAME"),
                rs.getString("WORKFLOW_ACTIVITY_INVOCATION_ID"),
                Instant.ofEpochMilli(rs.getTimestamp("CREATED_AT").getTime()),
                Instant.ofEpochMilli(rs.getTimestamp("UPDATED_AT").getTime()),
                Instant.ofEpochMilli(rs.getTimestamp("STARTED_AT").getTime()),
                rs.getInt("ATTEMPTS"));
    }

}
