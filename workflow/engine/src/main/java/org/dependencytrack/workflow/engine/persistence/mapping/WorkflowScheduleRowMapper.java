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
package org.dependencytrack.workflow.engine.persistence.mapping;

import org.dependencytrack.workflow.engine.api.WorkflowSchedule;
import org.dependencytrack.workflow.proto.payload.v1.Payload;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

import static org.dependencytrack.workflow.engine.persistence.mapping.MappingUtil.mapJsonEncodedMap;
import static org.dependencytrack.workflow.engine.persistence.mapping.MappingUtil.mapNullableInteger;

public final class WorkflowScheduleRowMapper implements RowMapper<WorkflowSchedule> {

    @Override
    public WorkflowSchedule map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new WorkflowSchedule(
                rs.getString("name"),
                rs.getString("cron"),
                rs.getString("workflow_name"),
                rs.getInt("workflow_version"),
                rs.getString("concurrency_group_id"),
                mapNullableInteger(rs, "priority"),
                mapJsonEncodedMap(rs, ctx, "labels", String.class, String.class),
                ctx.findColumnMapperFor(Payload.class).orElseThrow().map(rs, "argument", ctx),
                ctx.findColumnMapperFor(Instant.class).orElseThrow().map(rs, "created_at", ctx),
                ctx.findColumnMapperFor(Instant.class).orElseThrow().map(rs, "updated_at", ctx),
                ctx.findColumnMapperFor(Instant.class).orElseThrow().map(rs, "last_fired_at", ctx),
                ctx.findColumnMapperFor(Instant.class).orElseThrow().map(rs, "next_fire_at", ctx));
    }

}
