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

import alpine.common.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.job.JobEngine;
import org.dependencytrack.job.TransientJobException;
import org.dependencytrack.workflow.persistence.WorkflowRunHistoryEntryRow;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_RUN_FAILED;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_RUN_REQUESTED;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_RUN_STARTED;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_STEP_RUN_COMPLETED;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_STEP_RUN_FAILED;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_STEP_RUN_QUEUED;
import static org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent.SubjectCase.WORKFLOW_STEP_RUN_STARTED;

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
            adminClient.createTopics(List.of(
                            new NewTopic("dtrack.event.job", 3, (short) 1),
                            new NewTopic("dtrack.event.workflow", 3, (short) 1)))
                    .all().get();
        }
    }

    /*@Test
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
    }*/

    @Test
    public void shouldReplayActivityResultsOnWorkflowRetry() throws Exception {
        final var workflowAttempts = new AtomicInteger(0);
        final var abcActivityExecutions = new AtomicInteger(0);
        final var xyzActivityExecutions = new AtomicInteger(0);

        try (final var jobEngine = new JobEngine();
             final var workflowEngine = new WorkflowEngine()) {
            jobEngine.start();

            jobEngine.<JsonNode, Void>registerWorker("workflow-foo", 1, jobCtx -> {
                final WorkflowRunContext<JsonNode> workflowRunCtx =
                        workflowEngine.getRunContext(jobCtx.workflowRunId());
                Logger.getLogger(getClass()).info("Running workflow with arguments: " + jobCtx.arguments());

                final JsonNode foo = workflowRunCtx.callActivity("abc", "123",
                        JsonNodeFactory.instance.objectNode().put("hello", "world"), JsonNode.class).get();
                Logger.getLogger(getClass()).info("Activity abc completed with result: " + foo);

                if (workflowAttempts.incrementAndGet() < 2) {
                    throw new TransientJobException("Technical Difficulties");
                }

                final Object bar = workflowRunCtx.callActivity("xyz", "321", null, null).get();
                Logger.getLogger(getClass()).info("Activity xyz completed with result: " + bar);

                return Optional.empty();
            });

            jobEngine.<JsonNode, JsonNode>registerWorker("workflow-activity-abc", 1, jobCtx -> {
                final JsonNode arguments = jobCtx.arguments();
                Logger.getLogger(getClass()).info("Activity abc called with arguments: " + arguments);
                abcActivityExecutions.incrementAndGet();
                return Optional.of(JsonNodeFactory.instance.objectNode().put("hey", 666));
            });

            jobEngine.<JsonNode, Void>registerWorker("workflow-activity-xyz", 1, jobCtx -> {
                Logger.getLogger(getClass()).info("Activity xyz called with arguments: " + jobCtx.arguments());
                xyzActivityExecutions.incrementAndGet();
                return Optional.empty();
            });

            workflowEngine.start();
            final UUID workflowRunId = workflowEngine.startWorkflow(
                    new StartWorkflowOptions<ObjectNode>("foo")
                            .withArguments(JsonNodeFactory.instance.objectNode()
                                    .put("projectName", "acme-app")));

            await("Workflow completion")
                    .atMost(Duration.ofSeconds(15))
                    .untilAsserted(() -> {
                        final List<WorkflowRunHistoryEntryRow> history =
                                workflowEngine.getWorkflowRunHistory(workflowRunId);
                        assertThat(history).last().satisfies(
                                // TODO: Should be WORKFLOW_RUN_COMPLETED
                                event -> assertThat(event.eventType()).isEqualTo(WORKFLOW_STEP_RUN_COMPLETED.name()));
                    });

            assertThat(workflowAttempts.get()).isEqualTo(2);
            assertThat(abcActivityExecutions.get()).isEqualTo(1);
            assertThat(xyzActivityExecutions.get()).isEqualTo(1);
        }
    }

    @Test
    public void shouldRecordWorkflowAsFailedWhenWorkflowRunStepFails() throws Exception {
        try (final var jobEngine = new JobEngine();
             final var workflowEngine = new WorkflowEngine()) {
            jobEngine.start();
            jobEngine.registerWorker("workflow-foo", 1, jobCtx -> {
                throw new IllegalStateException("Broken beyond repair");
            });

            workflowEngine.start();
            final UUID workflowRunId = workflowEngine.startWorkflow(new StartWorkflowOptions<>("foo"));

            await("Workflow failure")
                    .atMost(Duration.ofSeconds(15))
                    .untilAsserted(() -> {
                        final List<WorkflowRunHistoryEntryRow> history =
                                workflowEngine.getWorkflowRunHistory(workflowRunId);
                        assertThat(history).satisfiesExactly(
                                event -> assertThat(event.eventType()).isEqualTo(WORKFLOW_RUN_REQUESTED.name()),
                                event -> assertThat(event.eventType()).isEqualTo(WORKFLOW_RUN_STARTED.name()),
                                event -> assertThat(event.eventType()).isEqualTo(WORKFLOW_STEP_RUN_QUEUED.name()),
                                event -> assertThat(event.eventType()).isEqualTo(WORKFLOW_STEP_RUN_STARTED.name()),
                                event -> assertThat(event.eventType()).isEqualTo(WORKFLOW_STEP_RUN_FAILED.name()),
                                event -> assertThat(event.eventType()).isEqualTo(WORKFLOW_RUN_FAILED.name()));
                    });
        }
    }

}