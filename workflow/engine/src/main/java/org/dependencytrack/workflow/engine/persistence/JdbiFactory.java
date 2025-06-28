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
package org.dependencytrack.workflow.engine.persistence;

import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.api.WorkflowSchedule;
import org.dependencytrack.workflow.engine.persistence.mapping.PolledActivityTaskRowMapper;
import org.dependencytrack.workflow.engine.persistence.mapping.PolledWorkflowEventRowMapper;
import org.dependencytrack.workflow.engine.persistence.mapping.PolledWorkflowRunRowMapper;
import org.dependencytrack.workflow.engine.persistence.mapping.ProtobufColumnMapper;
import org.dependencytrack.workflow.engine.persistence.mapping.WorkflowEventArgumentFactory;
import org.dependencytrack.workflow.engine.persistence.mapping.WorkflowEventSqlArrayType;
import org.dependencytrack.workflow.engine.persistence.mapping.WorkflowPayloadSqlArrayType;
import org.dependencytrack.workflow.engine.persistence.mapping.WorkflowScheduleRowMapper;
import org.dependencytrack.workflow.engine.persistence.model.PolledActivityTaskRow;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowEventRow;
import org.dependencytrack.workflow.engine.persistence.model.PolledWorkflowRunRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunCountByNameAndStatusRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunHistoryRow;
import org.dependencytrack.workflow.engine.persistence.model.WorkflowRunRow;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
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
                // Ensure all required mappings are registered *once*
                // on startup. Defining these on a per-query basis imposes
                // additional overhead that is worth avoiding given how
                // frequently queries are being executed.
                .registerArgument(new WorkflowEventArgumentFactory())
                .registerArrayType(Duration.class, "interval")
                .registerArrayType(Instant.class, "timestamptz")
                .registerArrayType(WorkflowRunStatus.class, "workflow_run_status")
                .registerArrayType(new WorkflowEventSqlArrayType())
                .registerArrayType(new WorkflowPayloadSqlArrayType())
                .registerColumnMapper(
                        WorkflowEvent.class,
                        new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .registerColumnMapper(
                        WorkflowPayload.class,
                        new ProtobufColumnMapper<>(WorkflowPayload.parser()))
                .registerRowMapper(
                        WorkflowRunCountByNameAndStatusRow.class,
                        ConstructorMapper.of(WorkflowRunCountByNameAndStatusRow.class))
                .registerRowMapper(
                        WorkflowRunRow.class,
                        ConstructorMapper.of(WorkflowRunRow.class))
                .registerRowMapper(
                        PolledActivityTaskRow.class,
                        new PolledActivityTaskRowMapper())
                .registerRowMapper(
                        PolledWorkflowEventRow.class,
                        new PolledWorkflowEventRowMapper())
                .registerRowMapper(
                        PolledWorkflowRunRow.class,
                        new PolledWorkflowRunRowMapper())
                .registerRowMapper(
                        WorkflowRunHistoryRow.class,
                        ConstructorMapper.of(WorkflowRunHistoryRow.class))
                .registerRowMapper(
                        WorkflowSchedule.class,
                        new WorkflowScheduleRowMapper());
    }

}
