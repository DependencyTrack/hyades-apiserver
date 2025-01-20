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

import org.dependencytrack.workflow.framework.persistence.model.PolledWorkflowRunRow;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Collections;
import java.util.Set;
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
                getTags(rs));
    }

    private static Integer getPriority(final ResultSet rs) throws SQLException {
        final int priority = rs.getInt("priority");
        if (rs.wasNull()) {
            return null;
        }

        return priority;
    }

    private static Set<String> getTags(final ResultSet rs) throws SQLException {
        final Array array = rs.getArray("tags");
        if (array == null) {
            return Collections.emptySet();
        }

        if (array.getBaseType() != Types.VARCHAR) {
            throw new IllegalArgumentException("Expected array with base type VARCHAR, but got %s".formatted(
                    array.getBaseTypeName()));
        }

        return Set.of((String[]) array.getArray());
    }

}
