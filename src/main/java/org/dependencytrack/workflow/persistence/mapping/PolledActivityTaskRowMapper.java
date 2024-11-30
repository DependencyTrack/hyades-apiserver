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
package org.dependencytrack.workflow.persistence.mapping;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.persistence.model.PolledActivityTaskRow;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.nullableInt;

public class PolledActivityTaskRowMapper implements RowMapper<PolledActivityTaskRow> {

    private final ColumnMapper<WorkflowPayload> argumentColumnMapper =
            new ProtobufColumnMapper<>(WorkflowPayload.parser());

    @Override
    public PolledActivityTaskRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new PolledActivityTaskRow(
                rs.getObject("WORKFLOW_RUN_ID", UUID.class),
                rs.getInt("SCHEDULED_EVENT_ID"),
                rs.getString("ACTIVITY_NAME"),
                nullableInt(rs, "PRIORITY"),
                argumentColumnMapper.map(rs, "ARGUMENT", ctx),
                ctx.findColumnMapperFor(Instant.class).orElseThrow().map(rs, "LOCKED_UNTIL", ctx));
    }

}
