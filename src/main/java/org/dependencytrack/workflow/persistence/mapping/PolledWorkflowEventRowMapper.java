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

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.persistence.model.PolledWorkflowEventRow;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

public class PolledWorkflowEventRowMapper implements RowMapper<PolledWorkflowEventRow> {

    private final ColumnMapper<WorkflowEvent> eventColumnMapper =
            new ProtobufColumnMapper<>(WorkflowEvent.parser());

    @Override
    public PolledWorkflowEventRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new PolledWorkflowEventRow(
                PolledWorkflowEventRow.EventType.valueOf(rs.getString("EVENT_TYPE")),
                rs.getObject("WORKFLOW_RUN_ID", UUID.class),
                eventColumnMapper.map(rs, "EVENT", ctx),
                rs.getInt("DEQUEUE_COUNT"));
    }

}
