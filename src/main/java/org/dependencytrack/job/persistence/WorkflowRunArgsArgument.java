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
package org.dependencytrack.job.persistence;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunArgs;
import org.jdbi.v3.core.argument.AbstractArgumentFactory;
import org.jdbi.v3.core.argument.Argument;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

public class WorkflowRunArgsArgument implements Argument {

    private final WorkflowRunArgs workflowRunArgs;

    WorkflowRunArgsArgument(final WorkflowRunArgs workflowRunArgs) {
        this.workflowRunArgs = workflowRunArgs;
    }

    @Override
    public void apply(final int position, final PreparedStatement statement, final StatementContext ctx) throws SQLException {
        if (workflowRunArgs == null) {
            statement.setNull(position, Types.LONGVARBINARY);
            return;
        }

        final byte[] argumentsBytes = workflowRunArgs.toByteArray();
        statement.setBytes(position, argumentsBytes);
    }

    public static class Factory extends AbstractArgumentFactory<WorkflowRunArgs> {

        public Factory() {
            super(Types.LONGVARBINARY);
        }

        @Override
        protected Argument build(final WorkflowRunArgs value, final ConfigRegistry config) {
            return new WorkflowRunArgsArgument(value);
        }

    }

}