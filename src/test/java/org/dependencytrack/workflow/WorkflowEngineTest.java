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

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.job.JobEngine;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.kafka.KafkaContainer;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.Workflows.WORKFLOW_BOM_UPLOAD_PROCESSING_V1;

public class WorkflowEngineTest extends PersistenceCapableTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Rule
    public KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.8.0");

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        environmentVariables.set("KAFKA_BOOTSTRAP_SERVERS", kafkaContainer.getBootstrapServers());

        try (final var adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.createTopics(List.of(new NewTopic("dtrack.event.job", 3, (short) 1))).all().get();
        }
    }

    @Test
    public void shouldHandleManyWorkflowRuns() throws Exception {
        try (final var jobEngine = new JobEngine();
             final var workflowEngine = new WorkflowEngine(jobEngine)) {
            jobEngine.start();

            workflowEngine.deploy(new WorkflowSpec("test", 1, List.of(
                    new WorkflowStepSpec("foo", WorkflowStepType.JOB, Collections.emptySet()),
                    new WorkflowStepSpec("bar", WorkflowStepType.JOB, Set.of("foo")))));
            workflowEngine.start();

            final var random = new SecureRandom();
            jobEngine.registerWorker("foo", 10, job -> {
                Thread.sleep(random.nextInt(10, 250));
                return Optional.empty();
            });
            jobEngine.registerWorker("bar", 1, job -> {
                Thread.sleep(random.nextInt(10, 250));
                return Optional.empty();
            });

            final var workflowsToStart = new ArrayList<StartWorkflowOptions>(1000);
            for (int i = 0; i < 1000; i++) {
                workflowsToStart.add(new StartWorkflowOptions("test", 1));
            }

            final List<WorkflowRunView> startedWorkflows = workflowEngine.startWorkflows(workflowsToStart);
            assertThat(startedWorkflows).hasSize(1000);

            await("Workflow run completion")
                    .atMost(360, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final long numCompletedWorkflowRuns = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT COUNT(*) FROM \"WORKFLOW_RUN\" WHERE \"STATUS\" = 'COMPLETED'")
                                .mapTo(Long.class)
                                .one());
                        assertThat(numCompletedWorkflowRuns).isEqualTo(1000);
                    });
        }
    }

    @Test
    public void shouldCancelDependantStepRunsOnFailure() throws Exception {
        try (final var jobEngine = new JobEngine();
             final var workflowEngine = new WorkflowEngine(jobEngine)) {
            jobEngine.start();

            workflowEngine.deploy(new WorkflowSpec("test", 1, List.of(
                    new WorkflowStepSpec("foo", WorkflowStepType.JOB, Collections.emptySet()),
                    new WorkflowStepSpec("bar", WorkflowStepType.JOB, Set.of("foo")),
                    new WorkflowStepSpec("baz", WorkflowStepType.JOB, Set.of("bar")))));
            workflowEngine.start();

            workflowEngine.startWorkflow(new StartWorkflowOptions("test", 1));

            jobEngine.registerWorker("foo", 1, job -> {
                throw new IllegalStateException("Just for testing");
            });

            await("Workflow completion")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final WorkflowRun workflowRun = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT * FROM \"WORKFLOW_RUN\"")
                                .map(ConstructorMapper.of(WorkflowRun.class))
                                .one());
                        assertThat(workflowRun.status()).isEqualTo(WorkflowRunStatus.FAILED);
                    });

            final List<WorkflowStepRun> workflowStepRuns = withJdbiHandle(
                    handle -> handle.createQuery("SELECT * FROM \"WORKFLOW_STEP_RUN\"")
                            .map(ConstructorMapper.of(WorkflowStepRun.class))
                            .list());
            assertThat(workflowStepRuns).satisfiesExactlyInAnyOrder(
                    stepRun -> {
                        assertThat(stepRun.status()).isEqualTo(WorkflowStepRunStatus.FAILED);
                        assertThat(stepRun.failureReason()).isEqualTo("Job failed: Just for testing");
                    },
                    stepRun -> assertThat(stepRun.status()).isEqualTo(WorkflowStepRunStatus.CANCELLED),
                    stepRun -> assertThat(stepRun.status()).isEqualTo(WorkflowStepRunStatus.CANCELLED));
        }
    }

    @Test
    public void shouldDeployWorkflowAndReturnCompleteView() throws Exception {
        try (final var jobEngine = new JobEngine();
             final var workflowEngine = new WorkflowEngine(jobEngine)) {
            workflowEngine.deploy(WORKFLOW_BOM_UPLOAD_PROCESSING_V1);

            final WorkflowRunView workflowRun = workflowEngine.startWorkflow(new StartWorkflowOptions(
                    WORKFLOW_BOM_UPLOAD_PROCESSING_V1.name(),
                    WORKFLOW_BOM_UPLOAD_PROCESSING_V1.version()));

            assertThat(workflowRun.workflowName()).isEqualTo("bom-upload-processing");
            assertThat(workflowRun.workflowVersion()).isEqualTo(1);
            assertThat(workflowRun.token()).isNotNull();
            assertThat(workflowRun.status()).isEqualTo(WorkflowRunStatus.PENDING);
            assertThat(workflowRun.createdAt()).isNotNull();
            assertThat(workflowRun.startedAt()).isNull();
            assertThat(workflowRun.steps()).satisfiesExactlyInAnyOrder(
                    step -> {
                        assertThat(step.stepName()).isEqualTo("consume-bom");
                        assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                        assertThat(step.createdAt()).isNotNull();
                        assertThat(step.startedAt()).isNull();
                    },
                    step -> {
                        assertThat(step.stepName()).isEqualTo("process-bom");
                        assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                        assertThat(step.createdAt()).isNotNull();
                        assertThat(step.startedAt()).isNull();
                    },
                    step -> {
                        assertThat(step.stepName()).isEqualTo("analyze-vulns");
                        assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                        assertThat(step.createdAt()).isNotNull();
                        assertThat(step.startedAt()).isNull();
                    },
                    step -> {
                        assertThat(step.stepName()).isEqualTo("evaluate-policies");
                        assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                        assertThat(step.createdAt()).isNotNull();
                        assertThat(step.startedAt()).isNull();
                    },
                    step -> {
                        assertThat(step.stepName()).isEqualTo("update-metrics");
                        assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                        assertThat(step.createdAt()).isNotNull();
                        assertThat(step.startedAt()).isNull();
                    });
        }
    }

}