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
import org.dependencytrack.workflow.WorkflowSubsystemInitializer.RandomlyFailingActivityRunner;
import org.dependencytrack.workflow.model.StartWorkflowOptions;
import org.dependencytrack.workflow.model.WorkflowEventType;
import org.dependencytrack.workflow.model.WorkflowRun;
import org.dependencytrack.workflow.model.WorkflowRunStatus;
import org.dependencytrack.workflow.persistence.WorkflowRunLogEntryRow;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.kafka.KafkaContainer;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

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
            adminClient.createTopics(List.of(new NewTopic("dtrack.event.workflow", 3, (short) 1))).all().get();
        }
    }

    @Test
    @SuppressWarnings("Convert2Lambda")
    public void shouldHandleManyWorkflowRuns() throws Exception {
        try (final var engine = new WorkflowEngine()) {
            engine.start();

            final var random = new SecureRandom();
            engine.registerWorkflowRunner("foo", 10, new WorkflowRunner<Void, Void>() {
                @Override
                public Optional<Void> run(final WorkflowRunContext<Void> ctx) {
                    ctx.callActivity("bar", "666", null, Void.class, Duration.ofSeconds(1));
                    return Optional.empty();
                }
            });

            engine.registerActivityRunner("bar", 10, new RandomlyFailingActivityRunner(random));

            final var futures = new ArrayList<CompletableFuture<?>>(1000);
            for (int i = 0; i < 1000; i++) {
                futures.add(engine.startWorkflow(new StartWorkflowOptions<>("foo", 1)));
            }

            CompletableFuture.allOf(futures.toArray(new CompletableFuture<?>[0])).join();

            await("Workflow run completion")
                    .atMost(360, TimeUnit.SECONDS)
                    .pollInterval(Duration.ofSeconds(3))
                    .untilAsserted(() -> {
                        final long numCompletedWorkflowRuns = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT COUNT(*) FROM \"WORKFLOW_RUN\" WHERE \"STATUS\" IN ('COMPLETED', 'FAILED')")
                                .mapTo(Long.class)
                                .one());
                        Logger.getLogger(getClass()).info("Completed executions: " + numCompletedWorkflowRuns);
                        assertThat(numCompletedWorkflowRuns).isEqualTo(1000);
                    });
        }
    }

    @Test
    @SuppressWarnings("Convert2Lambda")
    public void shouldSuspendWhileWaitingForFunctionResult() throws Exception {
        try (final var engine = new WorkflowEngine()) {
            engine.start();

            engine.registerWorkflowRunner("foo", 1, new WorkflowRunner<Void, JsonNode>() {
                @Override
                public Optional<JsonNode> run(final WorkflowRunContext<Void> ctx) {
                    final JsonNode functionArguments = JsonNodeFactory.instance.objectNode().put("hello", "world");
                    final ObjectNode functionResult = ctx.callActivity(
                            "abc", "123", functionArguments, ObjectNode.class, Duration.ofSeconds(1));

                    functionResult.put("execution", "done");
                    return Optional.of(functionResult);
                }
            });

            engine.registerActivityRunner("abc", 1, new WorkflowActivityRunner<ObjectNode, ObjectNode>() {
                @Override
                public Optional<ObjectNode> run(final WorkflowActivityContext<ObjectNode> ctx) {
                    final var argObject = ctx.arguments().orElseThrow();
                    argObject.put("hello", "dlrow");
                    return Optional.of(argObject);
                }
            });

            final WorkflowRun workflowRun = engine.startWorkflow(
                    new StartWorkflowOptions<Void>("foo", 1)).join();

            await("Workflow run completion")
                    .atMost(Duration.ofSeconds(15))
                    .untilAsserted(() -> {
                        final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                        assertThat(currentWorkflowRun).isNotNull();
                        assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                        assertThatJson(currentWorkflowRun.result()).isEqualTo(/* language=JSON */ """
                                {
                                  "hello": "dlrow",
                                  "execution": "done"
                                }
                                """);
                    });

            assertThat(engine.getWorkflowRunLog(workflowRun.id())).satisfiesExactly(
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.RUN_REQUESTED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.RUN_QUEUED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.RUN_STARTED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_REQUESTED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.RUN_SUSPENDED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_QUEUED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_STARTED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_COMPLETED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.RUN_RESUMED),
                    entry -> assertThat(entry.eventType()).isEqualTo(WorkflowEventType.RUN_COMPLETED));
        }
    }

    @Test
    @SuppressWarnings("Convert2Lambda")
    public void shouldReplayFunctionResultsOnWorkflowRetry() throws Exception {
        final var workflowAttempts = new AtomicInteger(0);

        try (final var engine = new WorkflowEngine()) {
            engine.start();

            engine.registerWorkflowRunner("foo", 1, new WorkflowRunner<JsonNode, Void>() {
                @Override
                public Optional<Void> run(final WorkflowRunContext<JsonNode> ctx) {
                    final JsonNode functionArguments = JsonNodeFactory.instance.objectNode().put("hello", "world");
                    ctx.callActivity("abc", "123", functionArguments, JsonNode.class, Duration.ofSeconds(1));

                    if (workflowAttempts.incrementAndGet() < 2) {
                        throw new AssertionError("Technical Difficulties");
                    }

                    ctx.callActivity("xyz", "321", null, null, Duration.ofSeconds(1));

                    return Optional.empty();
                }
            });

            engine.registerActivityRunner("abc", 1, new WorkflowActivityRunner<JsonNode, JsonNode>() {
                @Override
                public Optional<JsonNode> run(final WorkflowActivityContext<JsonNode> ctx) {
                    return Optional.of(JsonNodeFactory.instance.objectNode().put("hey", 666));
                }
            });

            engine.registerActivityRunner("xyz", 1, new WorkflowActivityRunner<JsonNode, Void>() {
                @Override
                public Optional<Void> run(final WorkflowActivityContext<JsonNode> ctx) {
                    return Optional.empty();
                }
            });

            final WorkflowRun workflowRun = engine.startWorkflow(
                    new StartWorkflowOptions<ObjectNode>("foo", 1)
                            .withArguments(JsonNodeFactory.instance.objectNode()
                                    .put("projectName", "acme-app"))).join();

            await("Workflow run completion")
                    .atMost(Duration.ofSeconds(15))
                    .untilAsserted(() -> {
                        final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                        assertThat(currentWorkflowRun).isNotNull();
                        assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                    });

            final List<WorkflowRunLogEntryRow> workflowRunLog = engine.getWorkflowRunLog(workflowRun.id());
            assertThat(workflowRunLog).satisfiesExactly(
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_REQUESTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_QUEUED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_REQUESTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_SUSPENDED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_QUEUED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_COMPLETED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_RESUMED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_FAILED_TRANSIENT),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_REQUESTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_SUSPENDED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_QUEUED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_COMPLETED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_RESUMED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_COMPLETED));
        }
    }

    @Test
    @SuppressWarnings("Convert2Lambda")
    public void shouldReplayLocalFunctionResultsOnWorkflowRetry() throws Exception {
        final var workflowAttempts = new AtomicInteger(0);

        try (final var engine = new WorkflowEngine()) {
            engine.start();

            engine.registerWorkflowRunner("foo", 1, new WorkflowRunner<JsonNode, Void>() {
                @Override
                public Optional<Void> run(final WorkflowRunContext<JsonNode> ctx) throws Exception {
                    final var abcArguments = JsonNodeFactory.instance.objectNode().put("hello", "world");
                    final JsonNode ignoredAbcResult = ctx.callLocalActivity("abc", "123", abcArguments, JsonNode.class,
                            args -> JsonNodeFactory.instance.objectNode().put("hey", 666));

                    if (workflowAttempts.incrementAndGet() < 2) {
                        throw new AssertionError("Technical Difficulties");
                    }

                    final Object ignoredXyzResult = ctx.callLocalActivity("xyz", "321", null, Void.class, args -> null);

                    return Optional.empty();
                }
            });

            final WorkflowRun workflowRun = engine.startWorkflow(
                    new StartWorkflowOptions<ObjectNode>("foo", 1)
                            .withArguments(JsonNodeFactory.instance.objectNode()
                                    .put("projectName", "acme-app"))).join();

            await("Workflow run completion")
                    .atMost(Duration.ofSeconds(15))
                    .untilAsserted(() -> {
                        final WorkflowRun currentWorkflowRun = engine.getWorkflowRun(workflowRun.id());
                        assertThat(currentWorkflowRun).isNotNull();
                        assertThat(currentWorkflowRun.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                    });

            final List<WorkflowRunLogEntryRow> workflowRunLog = engine.getWorkflowRunLog(workflowRun.id());
            assertThat(workflowRunLog).satisfiesExactly(
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_REQUESTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_QUEUED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_COMPLETED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_FAILED_TRANSIENT),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.ACTIVITY_RUN_COMPLETED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_COMPLETED));
        }
    }

    @Test
    @SuppressWarnings("Convert2Lambda")
    public void shouldRecordWorkflowAsFailedWhenExecutionFails() throws Exception {
        try (final var engine = new WorkflowEngine()) {
            engine.start();
            engine.registerWorkflowRunner("foo", 1, new WorkflowRunner<Void, Void>() {
                @Override
                public Optional<Void> run(final WorkflowRunContext<Void> ctx) {
                    throw new IllegalStateException("Broken beyond repair");
                }
            });

            final WorkflowRun workflowRun = engine.startWorkflow(
                    new StartWorkflowOptions<>("foo", 1)).join();

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

            final List<WorkflowRunLogEntryRow> workflowRunLog = engine.getWorkflowRunLog(workflowRun.id());
            assertThat(workflowRunLog).satisfiesExactly(
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_REQUESTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_QUEUED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_STARTED),
                    event -> assertThat(event.eventType()).isEqualTo(WorkflowEventType.RUN_FAILED));
        }
    }

}