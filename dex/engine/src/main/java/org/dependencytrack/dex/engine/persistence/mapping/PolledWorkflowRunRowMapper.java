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
package org.dependencytrack.dex.engine.persistence.mapping;

import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import static org.dependencytrack.dex.engine.persistence.mapping.MappingUtil.mapJsonEncodedMap;

public final class PolledWorkflowRunRowMapper implements RowMapper<PolledWorkflowTask> {

    @Override
    public PolledWorkflowTask map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return new PolledWorkflowTask(
                rs.getObject("id", UUID.class),
                rs.getString("workflow_name"),
                rs.getInt("workflow_version"),
                rs.getString("queue_name"),
                rs.getString("concurrency_group_id"),
                rs.getInt("priority"),
                mapJsonEncodedMap(rs, ctx, "labels", String.class, String.class));
    }

}
