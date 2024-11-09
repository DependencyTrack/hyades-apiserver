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

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.jdbi.v3.core.argument.AbstractArgumentFactory;
import org.jdbi.v3.core.argument.Argument;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

final class WorkflowEventArgument implements Argument {

    static final class Factory extends AbstractArgumentFactory<WorkflowEvent> {

        Factory() {
            super(Types.LONGVARBINARY);
        }

        @Override
        protected Argument build(final WorkflowEvent value, final ConfigRegistry config) {
            return new WorkflowEventArgument(value);
        }

    }

    private final WorkflowEvent workflowEvent;

    private WorkflowEventArgument(final WorkflowEvent workflowEvent) {
        this.workflowEvent = workflowEvent;
    }

    @Override
    public void apply(final int position, final PreparedStatement ps, final StatementContext ctx) throws SQLException {
        if (workflowEvent == null) {
            ps.setNull(position, Types.LONGVARBINARY);
            return;
        }

        final byte[] eventBytes = workflowEvent.toByteArray();
        ps.setBytes(position, eventBytes);
    }

}
