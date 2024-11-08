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
package org.dependencytrack.workflow.persistence;

import org.dependencytrack.workflow.model.WorkflowTaskStatus;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.nullableInstant;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.nullableInteger;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.nullableUuid;

public class WorkflowTaskRowMapper implements RowMapper<WorkflowTaskRow> {

    @Override
    public WorkflowTaskRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new WorkflowTaskRow(
                rs.getObject("ID", UUID.class),
                WorkflowTaskStatus.valueOf(rs.getString("STATUS")),
                rs.getString("QUEUE"),
                nullableInteger(rs, "PRIORITY"),
                Instant.ofEpochMilli(rs.getTimestamp("SCHEDULED_FOR").getTime()),
                nullableUuid(rs, "WORKFLOW_RUN_ID"),
                nullableUuid(rs, "ACTIVITY_RUN_ID"),
                rs.getString("ACTIVITY_NAME"),
                rs.getString("ACTIVITY_INVOCATION_ID"),
                nullableUuid(rs, "INVOKING_TASK_ID"),
                rs.getString("ARGUMENTS"),
                rs.getString("RESULT"),
                rs.getString("FAILURE_DETAILS"),
                rs.getInt("ATTEMPT"),
                Instant.ofEpochMilli(rs.getDate("CREATED_AT").getTime()),
                nullableInstant(rs, "UPDATED_AT"),
                nullableInstant(rs, "STARTED_AT"),
                nullableInstant(rs, "ENDED_AT"));
    }

}
