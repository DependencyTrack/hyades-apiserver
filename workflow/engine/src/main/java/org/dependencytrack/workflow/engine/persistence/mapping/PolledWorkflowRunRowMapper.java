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

import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowRunRow;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

public class PolledWorkflowRunRowMapper implements RowMapper<PolledWorkflowRunRow> {

    @Override
    public PolledWorkflowRunRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new PolledWorkflowRunRow(
                rs.getObject("id", UUID.class),
                rs.getString("workflow_name"),
                rs.getInt("workflow_version"),
                rs.getString("concurrency_group_id"),
                getPriority(rs),
                getLabels(rs, ctx));
    }

    private static Integer getPriority(final ResultSet rs) throws SQLException {
        final int priority = rs.getInt("priority");
        if (rs.wasNull()) {
            return null;
        }

        return priority;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> getLabels(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final String labelsJson = rs.getString("labels");
        if (rs.wasNull()) {
            return Collections.emptyMap();
        }

        final TypedJsonMapper jsonMapper = ctx
                .getConfig(JsonConfig.class).getJsonMapper()
                .forType(new GenericType<Map<String, String>>() {}.getType(), ctx.getConfig());

        return (Map<String, String>) jsonMapper.fromJson(labelsJson, ctx.getConfig());
    }

}
