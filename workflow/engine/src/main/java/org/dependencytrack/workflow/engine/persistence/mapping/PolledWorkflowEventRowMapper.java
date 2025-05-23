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

import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEventRow;
import org.dependencytrack.workflow.proto.v1.WorkflowEvent;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

public class PolledWorkflowEventRowMapper implements RowMapper<PolledWorkflowEventRow> {

    @Override
    public PolledWorkflowEventRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new PolledWorkflowEventRow(
                PolledWorkflowEventRow.EventType.valueOf(rs.getString("event_type")),
                rs.getObject("workflow_run_id", UUID.class),
                ctx.findColumnMapperFor(WorkflowEvent.class).orElseThrow().map(rs, "event", ctx),
                rs.getInt("sequence_number"),
                rs.getInt("dequeue_count"));
    }

}
