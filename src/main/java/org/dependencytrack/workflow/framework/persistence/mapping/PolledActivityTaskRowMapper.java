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
package org.dependencytrack.workflow.framework.persistence.mapping;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.framework.persistence.model.PolledActivityTaskRow;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;

public class PolledActivityTaskRowMapper implements RowMapper<PolledActivityTaskRow> {

    @Override
    public PolledActivityTaskRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new PolledActivityTaskRow(
                rs.getObject("workflow_run_id", UUID.class),
                rs.getInt("scheduled_event_id"),
                rs.getString("activity_name"),
                getPriority(rs),
                ctx.findColumnMapperFor(WorkflowPayload.class).orElseThrow().map(rs, "argument", ctx),
                ctx.findColumnMapperFor(Instant.class).orElseThrow().map(rs, "locked_until", ctx));
    }

    private static Integer getPriority(final ResultSet rs) throws SQLException {
        final int priority = rs.getInt("priority");
        if (rs.wasNull()) {
            return null;
        }

        return priority;
    }

}
