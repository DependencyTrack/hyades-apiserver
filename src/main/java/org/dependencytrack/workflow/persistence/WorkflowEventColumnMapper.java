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

import com.google.protobuf.InvalidProtocolBufferException;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.serialization.SerializationException;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

public final class WorkflowEventColumnMapper implements ColumnMapper<WorkflowEvent> {

    @Override
    public WorkflowEvent map(final ResultSet rs, final int columnNumber, final StatementContext ctx) throws SQLException {
        final byte[] eventBytes = rs.getBytes(columnNumber);
        if (rs.wasNull()) {
            return null;
        }

        try {
            return WorkflowEvent.parseFrom(eventBytes);
        } catch (InvalidProtocolBufferException e) {
            throw new SerializationException("Failed to parse workflow event", e);
        }
    }

}
