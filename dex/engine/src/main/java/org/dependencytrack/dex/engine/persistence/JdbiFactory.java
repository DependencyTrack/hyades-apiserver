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
package org.dependencytrack.dex.engine.persistence;

import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.persistence.mapping.PolledActivityTaskRowMapper;
import org.dependencytrack.dex.engine.persistence.mapping.PolledWorkflowEventRowMapper;
import org.dependencytrack.dex.engine.persistence.mapping.PolledWorkflowRunRowMapper;
import org.dependencytrack.dex.engine.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.dex.engine.persistence.mapping.WorkflowEventArgumentFactory;
import org.dependencytrack.dex.engine.persistence.mapping.WorkflowEventSqlArrayType;
import org.dependencytrack.dex.engine.persistence.mapping.WorkflowPayloadSqlArrayType;
import org.dependencytrack.dex.engine.persistence.model.PolledActivityTask;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvent;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.persistence.model.WorkflowRunMetadataRow;
import org.dependencytrack.dex.proto.event.v1.Event;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.jackson2.Jackson2Plugin;
import org.jdbi.v3.postgres.PostgresPlugin;

import javax.sql.DataSource;
import java.time.Duration;
import java.time.Instant;

public final class JdbiFactory {

    private JdbiFactory() {
    }

    public static Jdbi create(final DataSource dataSource) {
        return Jdbi
                .create(dataSource)
                .installPlugin(new Jackson2Plugin())
                .installPlugin(new PostgresPlugin())
                .setTemplateEngine(FreemarkerEngine.instance())
                .configure(SqlStatements.class, statementsCfg -> statementsCfg.setQueryTimeout(10))
                // Ensure all required mappings are registered *once*
                // on startup. Defining these on a per-query basis imposes
                // additional overhead that is worth avoiding given how
                // frequently queries are being executed.
                .registerArgument(new WorkflowEventArgumentFactory())
                .registerArrayType(Duration.class, "interval")
                .registerArrayType(Instant.class, "timestamptz")
                .registerArrayType(WorkflowRunStatus.class, "dex_workflow_run_status")
                .registerArrayType(new WorkflowEventSqlArrayType())
                .registerArrayType(new WorkflowPayloadSqlArrayType())
                .registerColumnMapper(
                        Event.class,
                        new ProtobufColumnMapper<>(Event.parser()))
                .registerColumnMapper(
                        Payload.class,
                        new ProtobufColumnMapper<>(Payload.parser()))
                .registerRowMapper(
                        WorkflowRunCountByNameAndStatusRow.class,
                        ConstructorMapper.of(WorkflowRunCountByNameAndStatusRow.class))
                .registerRowMapper(
                        WorkflowRunMetadataRow.class,
                        ConstructorMapper.of(WorkflowRunMetadataRow.class))
                .registerRowMapper(
                        PolledActivityTask.class,
                        new PolledActivityTaskRowMapper())
                .registerRowMapper(
                        PolledWorkflowEvent.class,
                        new PolledWorkflowEventRowMapper())
                .registerRowMapper(
                        PolledWorkflowTask.class,
                        new PolledWorkflowRunRowMapper())
                .registerRowMapper(
                        WorkflowRunHistoryEntry.class,
                        ConstructorMapper.of(WorkflowRunHistoryEntry.class));
    }

}
