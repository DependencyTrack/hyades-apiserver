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
package org.dependencytrack.workflow;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs;
import org.dependencytrack.proto.internal.workflow.payload.v1.ProjectIdentity;
import org.dependencytrack.workflow.engine.api.ActivityGroup;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowGroup;
import org.dependencytrack.workflow.engine.api.WorkflowRun;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.workflow.testing.WorkflowTestRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.workflow.mapping.PayloadModelConverter.convertToProjectIdentity;

public class CloneProjectWorkflowTest extends PersistenceCapableTest {

    @Rule
    public final WorkflowTestRule workflowTestRule = new WorkflowTestRule(postgresContainer);

    private WorkflowEngine engine;

    @Before
    public void before() throws Exception {
        super.before();

        engine = workflowTestRule.getEngine();

        engine.registerWorkflow(
                new CloneProjectWorkflow(),
                protoConverter(CloneProjectArgs.class),
                protoConverter(ProjectIdentity.class),
                Duration.ofSeconds(5));
        engine.mountWorkflows(
                new WorkflowGroup("all")
                        .withWorkflow(CloneProjectWorkflow.class));

        engine.registerActivity(
                new CloneProjectActivity(),
                protoConverter(CloneProjectArgs.class),
                protoConverter(ProjectIdentity.class),
                Duration.ofSeconds(3),
                false);
        engine.registerActivity(
                new UpdateProjectMetricsActivity(),
                protoConverter(ProjectIdentity.class),
                voidConverter(),
                Duration.ofSeconds(3),
                false);
        engine.mountActivities(
                new ActivityGroup("all")
                        .withActivity(CloneProjectActivity.class)
                        .withActivity(UpdateProjectMetricsActivity.class)
                        .withMaxConcurrency(2));

        engine.start();
    }

    @Test
    public void shouldFailWhenArgumentIsNull() {
        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>(CloneProjectWorkflow.class)
                        .withArgument(null));

        final WorkflowRun run = workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("No argument provided");
    }

    @Test
    public void shouldClone() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>(CloneProjectWorkflow.class)
                        .withArgument(
                                CloneProjectArgs.newBuilder()
                                        .setSourceProject(convertToProjectIdentity(project))
                                        .setTargetVersion("2.0.0")
                                        .build()));

        final WorkflowRun run = workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();

        final ProjectIdentity clonedProjectIdentity =
                protoConverter(ProjectIdentity.class).convertFromPayload(run.result());
        assertThat(clonedProjectIdentity).isNotNull();
        assertThat(clonedProjectIdentity.getUuid()).isNotEmpty();
        assertThat(clonedProjectIdentity.getName()).isEqualTo("acme-app");
        assertThat(clonedProjectIdentity.getVersion()).isEqualTo("2.0.0");

        final Project clonedProject = qm.getProject(clonedProjectIdentity.getUuid());
        assertThat(clonedProject).isNotNull();

        final ProjectMetrics metrics = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(clonedProject.getId()));
        assertThat(metrics).isNull();
    }

    @Test
    public void shouldCloneAndUpdateMetricsWhenRequested() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>(CloneProjectWorkflow.class)
                        .withArgument(
                                CloneProjectArgs.newBuilder()
                                        .setSourceProject(convertToProjectIdentity(project))
                                        .setTargetVersion("2.0.0")
                                        .setUpdateTargetMetrics(true)
                                        .build()));

        final WorkflowRun run = workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();

        final ProjectIdentity clonedProjectIdentity =
                protoConverter(ProjectIdentity.class).convertFromPayload(run.result());
        assertThat(clonedProjectIdentity).isNotNull();
        assertThat(clonedProjectIdentity.getUuid()).isNotEmpty();
        assertThat(clonedProjectIdentity.getName()).isEqualTo("acme-app");
        assertThat(clonedProjectIdentity.getVersion()).isEqualTo("2.0.0");

        final Project clonedProject = qm.getProject(clonedProjectIdentity.getUuid());
        assertThat(clonedProject).isNotNull();

        final ProjectMetrics metrics = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(clonedProject.getId()));
        assertThat(metrics).isNotNull();
    }

    @Test
    public void shouldFailWhenTargetProjectAlreadyExists() {
        final var sourceProject = new Project();
        sourceProject.setName("acme-app");
        sourceProject.setVersion("1.0.0");
        qm.persist(sourceProject);

        final var targetProject = new Project();
        targetProject.setName("acme-app");
        targetProject.setVersion("2.0.0");
        qm.persist(targetProject);

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>(CloneProjectWorkflow.class)
                        .withArgument(
                                CloneProjectArgs.newBuilder()
                                        .setSourceProject(convertToProjectIdentity(sourceProject))
                                        .setTargetVersion("2.0.0")
                                        .build()));

        final WorkflowRun run = workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("Activity clone-project failed");
        assertThat(run.failure().getCause().getMessage()).isEqualTo("Project could not be cloned");
        assertThat(run.failure().getCause().getCause().getMessage()).isEqualTo(
                "Project was supposed to be cloned to version 2.0.0, but that version already exists");
    }

    @Test
    public void shouldFailWhenSourceProjectDoesNotExists() {
        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>(CloneProjectWorkflow.class)
                        .withArgument(
                                CloneProjectArgs.newBuilder()
                                        .setSourceProject(ProjectIdentity.newBuilder()
                                                .setUuid("fa29060e-3b89-4fdb-bc00-f85f090c0955")
                                                .setName("acme-app")
                                                .setVersion("1.0.0")
                                                .build())
                                        .setTargetVersion("2.0.0")
                                        .build()));

        final WorkflowRun run = workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("Activity clone-project failed");
        assertThat(run.failure().getCause().getMessage()).isEqualTo("Project could not be cloned");
        assertThat(run.failure().getCause().getCause().getMessage()).isEqualTo(
                "Project was supposed to be cloned, but it does not exist anymore");
    }

}