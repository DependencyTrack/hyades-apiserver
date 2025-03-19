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
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.ScheduleProjectAnalysesEvent;
import org.dependencytrack.workflow.framework.ScheduleWorkflowRunOptions;
import org.dependencytrack.workflow.payload.proto.v1alpha1.AnalyzeProjectArgs;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.WorkflowEngineInitializer.workflowEngine;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;

public class ProjectAnalysisSchedulerTask implements Subscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectAnalysisSchedulerTask.class);

    @Override
    public void inform(final Event event) {
        if (!(event instanceof ScheduleProjectAnalysesEvent(String initiator))) {
            return;
        }

        List<Project> projects = fetchNextProjectBatch(null);
        while (!projects.isEmpty()) {
            final var scheduleOptions = new ArrayList<ScheduleWorkflowRunOptions>(projects.size());
            for (final Project project : projects) {
                scheduleOptions.add(new ScheduleWorkflowRunOptions("analyze-project", 1)
                        .withLabels(Map.ofEntries(
                                Map.entry("project", project.uuid().toString()),
                                Map.entry("initiator", initiator)))
                        .withConcurrencyGroupId("analyze-project-" + project.uuid())
                        .withArgument(
                                AnalyzeProjectArgs.newBuilder()
                                        .setProject(org.dependencytrack.workflow.payload.proto.v1alpha1.Project.newBuilder()
                                                .setUuid(project.uuid().toString())
                                                .setName(project.name())
                                                .setVersion(project.version())
                                                .build())
                                        .build(),
                                protoConverter(AnalyzeProjectArgs.class)));
            }

            final List<UUID> scheduledRunIds = workflowEngine().scheduleWorkflowRuns(scheduleOptions);
            LOGGER.info("Scheduled {} project analysis workflow runs", scheduledRunIds.size());

            final long lastId = projects.getLast().id();
            projects = fetchNextProjectBatch(lastId);
        }
    }

    public record Project(
            long id,
            UUID uuid,
            String name,
            String version) {
    }

    private List<Project> fetchNextProjectBatch(final Long lastId) {
        // TODO: Filter by lastAnalysisAt (new column) so we don't schedule all projects on each invocation,
        //  but every project every $interval. That would distribute load more evenly.
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "ID"
                         , "UUID"
                         , "NAME"
                         , "VERSION"
                      FROM "PROJECT"
                     WHERE "ACTIVE"
                       AND (:lastId IS NULL OR "ID" > :lastId)
                     ORDER BY "ID"
                     LIMIT 1000
                    """);

            return query
                    .bind("lastId", lastId)
                    .map(ConstructorMapper.of(Project.class))
                    .list();
        });
    }

}
