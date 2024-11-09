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

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.model.StartWorkflowOptions;
import org.dependencytrack.workflow.model.WorkflowRun;
import org.dependencytrack.workflow.model.WorkflowRunStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.workflow.serialization.Serdes.jsonSerde;
import static org.dependencytrack.workflow.serialization.Serdes.voidSerde;

public class WorkflowEngineTest extends PersistenceCapableTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Rule
    public KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.8.0");

    private WorkflowEngine engine;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        environmentVariables.set("KAFKA_BOOTSTRAP_SERVERS", kafkaContainer.getBootstrapServers());

        try (final var adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.createTopics(List.of(new NewTopic("dtrack.event.workflow", 3, (short) 1))).all().get();
        }

        engine = new WorkflowEngine();
        engine.start();
    }

    @After
    @Override
    public void after() {
        if (engine != null) {
            assertThatNoException()
                    .isThrownBy(() -> engine.close());
        }

        super.after();
    }

    @Test
    public void shouldSuspendWhileWaitingForActivityResult() {
        engine.registerWorkflowRunner("foo", 1, voidSerde(), jsonSerde(ObjectNode.class), ctx -> {
            final ObjectNode activityArguments = JsonNodeFactory.instance.objectNode().put("hello", "world");
            final ObjectNode activityResult = ctx.callActivity("abc", "123",
                    activityArguments, jsonSerde(ObjectNode.class), jsonSerde(ObjectNode.class), Duration.ZERO).orElseThrow();

            activityResult.put("execution", "done");
            return Optional.of(activityResult);
        });

        engine.registerActivityRunner("abc", 1, jsonSerde(ObjectNode.class), jsonSerde(ObjectNode.class), ctx -> {
            final ObjectNode argObject = ctx.arguments().orElseThrow();
            argObject.put("hello", "dlrow");
            return Optional.of(argObject);
        });

        final WorkflowRun workflowRun = engine.startWorkflow(
                new StartWorkflowOptions("foo", 1)).join();

        await("Workflow run completion")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> {
                    final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                    assertThat(currentWorkflowRun).isNotNull();
                    assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                    assertThatJson(new String(currentWorkflowRun.result())).isEqualTo(/* language=JSON */ """
                            {
                              "hello": "dlrow",
                              "execution": "done"
                            }
                            """);
                });

        assertThat(engine.getWorkflowRunLog(workflowRun.id())).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_REQUESTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_QUEUED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_REQUESTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SUSPENDED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_QUEUED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_RESUMED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED));
    }

    @Test
    public void shouldWaitForActivityResultWhenWithinTimeout() {
        engine.registerWorkflowRunner("foo", 1, voidSerde(), jsonSerde(ObjectNode.class), ctx -> {
            final ObjectNode activityArguments = JsonNodeFactory.instance.objectNode().put("hello", "world");
            final ObjectNode activityResult = ctx.callActivity("abc", "123",
                    activityArguments, jsonSerde(ObjectNode.class), jsonSerde(ObjectNode.class), Duration.ofSeconds(15)).orElseThrow();

            activityResult.put("execution", "done");
            return Optional.of(activityResult);
        });

        engine.registerActivityRunner("abc", 1, jsonSerde(ObjectNode.class), jsonSerde(ObjectNode.class), ctx -> {
            final var argObject = ctx.arguments().orElseThrow();
            argObject.put("hello", "dlrow");
            return Optional.of(argObject);
        });

        final WorkflowRun workflowRun = engine.startWorkflow(
                new StartWorkflowOptions("foo", 1)).join();

        await("Workflow run completion")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> {
                    final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                    assertThat(currentWorkflowRun).isNotNull();
                    assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                    assertThatJson(new String(currentWorkflowRun.result())).isEqualTo(/* language=JSON */ """
                            {
                              "hello": "dlrow",
                              "execution": "done"
                            }
                            """);
                });

        assertThat(engine.getWorkflowRunLog(workflowRun.id())).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_REQUESTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_QUEUED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_REQUESTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_QUEUED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED));
    }

    @Test
    public void shouldReplayActivityResultsOnWorkflowRetry() {
        final var workflowAttempts = new AtomicInteger(0);

        engine.registerWorkflowRunner("foo", 1, voidSerde(), voidSerde(), ctx -> {
            ctx.callActivity("abc", "123", null, voidSerde(), voidSerde(), Duration.ZERO);

            if (workflowAttempts.incrementAndGet() < 2) {
                throw new AssertionError("Technical Difficulties");
            }

            ctx.callActivity("xyz", "321", null, voidSerde(), voidSerde(), Duration.ZERO);

            return Optional.empty();
        });

        engine.registerActivityRunner("abc", 1, voidSerde(), voidSerde(), ctx -> Optional.empty());
        engine.registerActivityRunner("xyz", 1, voidSerde(), voidSerde(), ctx -> Optional.empty());

        final WorkflowRun workflowRun = engine.startWorkflow(
                new StartWorkflowOptions("foo", 1)).join();

        await("Workflow run completion")
                .atMost(Duration.ofSeconds(30))
                .untilAsserted(() -> {
                    final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                    assertThat(currentWorkflowRun).isNotNull();
                    assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        final List<WorkflowEvent> workflowRunLog = engine.getWorkflowRunLog(workflowRun.id());
        assertThat(workflowRunLog).satisfiesExactly(
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_REQUESTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_QUEUED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_REQUESTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SUSPENDED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_QUEUED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_RESUMED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_FAILED);
                    assertThat(event.getRunFailed().hasNextAttemptAt()).isTrue();
                },
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_REQUESTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SUSPENDED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_QUEUED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_RESUMED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED));
    }

    @Test
    public void shouldReplayLocalActivityResultsOnWorkflowRetry() {
        final var workflowAttempts = new AtomicInteger(0);

        engine.registerWorkflowRunner("foo", 1, voidSerde(), voidSerde(), ctx -> {
            ctx.callLocalActivity("abc", "123", null, voidSerde(), voidSerde(), ignored -> null);

            if (workflowAttempts.incrementAndGet() < 2) {
                throw new AssertionError("Technical Difficulties");
            }

            ctx.callLocalActivity("xyz", "321", null, voidSerde(), voidSerde(), ignored -> null);

            return Optional.empty();
        });

        final WorkflowRun workflowRun = engine.startWorkflow(
                new StartWorkflowOptions("foo", 1)).join();

        await("Workflow run completion")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> {
                    final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                    assertThat(currentWorkflowRun).isNotNull();
                    assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        final List<WorkflowEvent> workflowRunLog = engine.getWorkflowRunLog(workflowRun.id());
        assertThat(workflowRunLog).satisfiesExactly(
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_REQUESTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_QUEUED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_COMPLETED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_FAILED);
                    assertThat(event.getRunFailed().hasNextAttemptAt()).isTrue();
                },
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_RUN_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED));
    }

    @Test
    public void shouldRecordWorkflowAsFailedWhenRunFails() {
        engine.registerWorkflowRunner("foo", 1, voidSerde(), voidSerde(), ctx -> {
            throw new IllegalStateException("Broken beyond repair");
        });

        final WorkflowRun workflowRun = engine.startWorkflow(
                new StartWorkflowOptions("foo", 1)).join();

        await("Workflow run completion")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                    assertThat(currentWorkflowRun).isNotNull();
                    assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.FAILED);
                    assertThat(currentWorkflowRun.failureDetails()).isEqualTo("Broken beyond repair");
                    assertThat(currentWorkflowRun.updatedAt()).isNotNull();
                    assertThat(currentWorkflowRun.endedAt()).isEqualTo(currentWorkflowRun.updatedAt());
                });

        final List<WorkflowEvent> workflowRunLog = engine.getWorkflowRunLog(workflowRun.id());
        assertThat(workflowRunLog).satisfiesExactly(
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_REQUESTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_QUEUED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_FAILED));
    }

}